// @ts-expect-error no types
import { get_gateway_ip } from 'network';
import { toMAC } from '@network-utils/arp-lookup';
import { toVendor } from '@network-utils/vendor-lookup';
import axios from 'axios';
import crypto from 'node:crypto';
import http from 'node:http';
import fs from 'node:fs';
import { URL } from 'node:url';

export async function getMacForIp(ip: string): Promise<{ mac: string; vendor?: string; ip: string } | null> {
    const mac = await toMAC(ip);
    if (mac) {
        return { mac, vendor: toVendor(mac), ip };
    }
    return null
}

export function getDefaultGateway(): Promise<string> {
    return new Promise((resolve, reject) => get_gateway_ip((err: string, ip: string) => {
        if (err) {
            return reject(err);
        }
        return resolve(ip);
    }));
}

export async function getFritzBoxInterfaces(ip: string, login: string, password: string) {

}

export async function getFritzBoxToken(ip: string, login: string, password: string) {
    try {
        const response = await axios(`http://${ip}/login_sid.lua`);
        if (response.data) {
            const challenge = response.data.match(/<Challenge>(.*?)<\/Challenge>/);
            if (challenge) {
                const challengeResponse = `${challenge[1]}-${password}`;
                const challengeResponseBuffer = Buffer.from(challengeResponse, 'utf16le');
                const challengeResponseHash = crypto.createHash('md5').update(challengeResponseBuffer).digest('hex');
                const response2 = await axios(`http://${ip}/login_sid.lua?username=${login}&response=${challengeResponseHash}`);
                if (response2.data) {
                    const sessionInfo = response2.data.match(/<SID>(.*?)<\/SID>/);
                    if (sessionInfo) {
                        return sessionInfo[1] !== '0000000000000000' ? sessionInfo[1] : null;
                    }
                }
            }
        }
    } catch (e) {
        console.error(e);
        return null;
    }

    return null;
}

function analyzePacket(context: {
    data: Buffer;
    packets: Buffer[];
}): boolean {
    const len = context.data.byteLength;
    // first 4 bytes are timestamp in seconds
    // next 4 bytes are timestamp in microseconds
    // next 4 bytes are packet length saved in file
    // next 4 bytes are packet length sent over the network
    if (len < 16) {
        return false;
    }

    const nextPackageLen = context.data.readUInt32BE(8);

    if (len < 16 + nextPackageLen) {
        return false;
    }

    // next 6 bytes are MAC address of a source
    // next 6 bytes are MAC address of destination
    let offset = 16 + 12;

    // next 2 bytes are Ethernet type
    const ethType = context.data.readUInt16BE(offset);
    offset += 2;
    let maxBytes = 0;
    // If IPv4
    if (ethType === 0x0800) {
        maxBytes = 20;
    }
    // If ICMP
    // if (ethType === 1) {
    //     return offset + 40;
    // }

    // If IPv6
    // if (ethType === 0x86DD) {
    //     return offset + 40;
    // }

    if (maxBytes) {
        if (nextPackageLen < maxBytes) {
            // remove from buffer nextPackageLen + 16 bytes
            context.packets.push(context.data.subarray(0, 16 + nextPackageLen));
        } else {
            const packet = context.data.subarray(0, 16 + maxBytes);
            // save new length in the packet
            packet.writeUInt32BE(maxBytes, 8);
            context.packets.push(packet);
        }
    }

    // remove this packet
    context.data = context.data.subarray(16 + nextPackageLen);

    return true;
}

const MAX_PACKET_LENGTH = 68;

export function startRecordingOnFritzBox(
    ip: string,
    sid: string,
    iface: string,
    MACs: string[],
    targetFile: string,
    onEnd: ((error: Error | null, packetCounter?: number) => void) | null,
    terminateContext?: {
        terminate: boolean,
        controller: AbortController | null,
    } | undefined | null,
    progress?: (packets: number) => void,
) {
    const filter = `ether host ${MACs.join(' || ')}`;

    const captureUrl = `http://${ip}/cgi-bin/capture_notimeout?ifaceorminor=${iface}&snaplen=${MAX_PACKET_LENGTH}&filter=${filter}&capture=Start&sid=${sid}`;

    let first = false;

    const context: {
        data: Buffer;
        packets: Buffer[];
    } = {
        data: Buffer.from([]),
        packets: [],
    }
    let timeout: NodeJS.Timeout | null = null;
    let packetCounter = 0;
    let lastProgress = Date.now();

    const informProgress = (_packets: number) => {
        const now = Date.now();
        if (now - lastProgress > 1000) {
            lastProgress = now;
            progress && progress(_packets);
        }
    };

    const executeOnEnd = (error: Error | null, packetCounter: number) => {
        timeout && clearTimeout(timeout);
        timeout = null;
        if (context.packets.length) {
            packetCounter += context.packets.length;
            fs.appendFileSync(targetFile, Buffer.concat(context.packets));
            context.packets = [];
        }
        onEnd && onEnd(error, packetCounter);
        onEnd = null;
    }

    // parse URL address
    const parsed = new URL(captureUrl);

    const controller = terminateContext?.controller || new AbortController();

    const req = http.request({
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: 'GET',
        signal: controller.signal,
    }, res => {
        res.on('data', (chunk: Buffer) => {
            // add data to buffer
            context.data = Buffer.concat([context.data, chunk]);
            console.log(chunk.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase());

            // if the header of PCAP file is not written yet
            if (!first) {
                // check if we have at least 6 bytes
                if (context.data.length > 6) {
                    first = true;
                    // write first 6 bytes to PCAP file
                    fs.writeFileSync(targetFile, context.data.subarray(0, 6));
                    context.data = context.data.subarray(6);
                }
                return;
            }

            let more = false;
            do {
                more = analyzePacket(context);
            } while (more);

            if (context.packets.length > 50) {
                // save it to file
                packetCounter += context.packets.length;
                fs.appendFileSync(targetFile, Buffer.concat(context.packets));
                context.packets = [];
                informProgress(packetCounter);
            } else if (context.packets.length) {
                timeout && clearTimeout(timeout);
                timeout = setTimeout(() => {
                    packetCounter += context.packets.length;
                    fs.appendFileSync(targetFile, Buffer.concat(context.packets));
                    context.packets = [];
                    informProgress(packetCounter);
                }, 1000);
            }

            if (terminateContext?.terminate) {
                controller.abort()
                executeOnEnd(null, packetCounter);
                return;
            }
        });

        res.on('end', () => executeOnEnd(null, packetCounter));

        res.on('error', (error: Error) => executeOnEnd(error, packetCounter));
    });

    req.on('error', error => executeOnEnd(error, packetCounter));
}

export function generateKeys(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
}

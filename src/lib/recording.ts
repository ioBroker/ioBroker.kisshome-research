import http from 'node:http';
import axios from 'axios';

export type Context = {
    terminate: boolean;
    controller: AbortController | null,
    packets: Buffer[];
    totalBytes: number;
    totalPackets: number;
    buffer?: Buffer;
};

export const MAX_PACKET_LENGTH = 1600;//68;
const debug = true;

function analyzePacket(context: Context): boolean {
    if (!context.buffer) {
        return false;
    }
    const len = context.buffer.byteLength || 0;
    // first 4 bytes are timestamp in seconds
    // next 4 bytes are timestamp in microseconds
    // next 4 bytes are packet length saved in file
    // next 4 bytes are packet length sent over the network
    if (len < 16) {
        return false;
    }

    if (debug) {
        const seconds = context.buffer.readUInt32LE(0);
        const microseconds = context.buffer.readUInt32LE(4);
        const packageLen = context.buffer.readUInt32LE(8);
        const packageLenSent = context.buffer.readUInt32LE(12);
        const MAC1 = context.buffer.subarray(16, 16 + 6);
        const MAC2 = context.buffer.subarray(22, 22 + 6);
        console.log(`Packet: ${new Date(seconds * 1000 + Math.round(microseconds / 1000)).toISOString()} ${packageLen} ${packageLenSent} ${MAC1.toString('hex')} => ${MAC2.toString('hex')}`);
    }

    const nextPackageLen = context.buffer.readUInt32LE(8);
    if (nextPackageLen > 10000) {
        // error of capturing
        throw new Error(`Packet length is too big: ${nextPackageLen}`);
    }

    if (len < 16 + nextPackageLen) {
        return false;
    }

    // next 6 bytes are MAC address of a source
    // next 6 bytes are MAC address of destination
    let offset = 16 + 12;

    // next 2 bytes are Ethernet type
    const ethType = context.buffer.readUInt16BE(offset);

    let maxBytes = 0;
    // If IPv4
    if (ethType === 0x0800) {
        maxBytes = 20 + 14; // 20 bytes of IP header + 14 bytes of Ethernet header
        // read protocol type
        const protocolType = context.buffer[offset + 11];
        if (protocolType === 6) {
            maxBytes += 32; // 32 bytes of TCP header
        } else if (protocolType === 17) {
            maxBytes += 8; // 8 bytes of UDP header
        } else if (protocolType === 1) {
            // icmp
            maxBytes = 0;
        } else {
            maxBytes = 0;
        }
    }

    // todo: which more protocols to collect?
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
            context.packets.push(context.buffer.subarray(0, 16 + nextPackageLen));
            context.totalBytes += 16 + nextPackageLen;
            if (debug) {
                console.log(`Saved packet: ${16 + nextPackageLen}`);
            }
        } else {
            const packet = context.buffer.subarray(0, 16 + maxBytes);
            // save new length in the packet
            packet.writeUInt32LE(maxBytes, 8);
            context.packets.push(packet);
            context.totalBytes += 16 + maxBytes;
            if (debug) {
                console.log(`Saved packet: ${16 + maxBytes}`);
            }
        }
        context.totalPackets++;
    }

    // remove this packet
    context.buffer = context.buffer.subarray(16 + nextPackageLen);

    return true;
}

export async function stopAllRecordingsOnFritzBox(
    ip: string,
    sid: string,
) {
    const captureUrl = `http://${ip.trim()}/cgi-bin/capture_notimeout?iface=stopall&capture=Stop&sid=${sid}`;
    const response = await axios.get(captureUrl);
    return response.data;
}

export function startRecordingOnFritzBox(
    ip: string,
    sid: string,
    iface: string,
    MACs: string[],
    onEnd: ((error: Error | null) => void) | null,
    context: Context,
    progress?: () => void,
) {
    let filter = `ether host ${MACs.join(' || ')}`;
    // enable all for tests
    filter = '';

    const captureUrl = `http://${ip.trim()}/cgi-bin/capture_notimeout?ifaceorminor=${encodeURIComponent(iface.trim())}&snaplen=${MAX_PACKET_LENGTH}${filter ? `&filter=${encodeURIComponent(filter)}` : ''}&capture=Start&sid=${sid}`;

    let first = false;

    context.buffer = Buffer.from([]);

    let timeout: NodeJS.Timeout | null = null;
    let lastProgress = Date.now();

    const informProgress = () => {
        const now = Date.now();
        if (now - lastProgress > 1000) {
            lastProgress = now;
            progress && progress();
        }
    };

    const executeOnEnd = (error: Error | null) => {
        console.log(`FINISH receiving of data...: ${error}`);
        timeout && clearTimeout(timeout);
        timeout = null;
        onEnd && onEnd(error);
        onEnd = null;
    }

    const controller = context.controller || new AbortController();
    context.controller = controller;

    console.log(`START capture: ${captureUrl}`);

    const req = http.request(captureUrl, {
        method: 'GET',
        signal: controller.signal,
    }, res => {
        if (res.statusCode !== 200) {
            if (res.statusCode === 401 || res.statusCode === 403) {
                executeOnEnd(new Error('Unauthorized'));
                return;
            }

            executeOnEnd(new Error(`Unexpected status code: ${res.statusCode}`));
            try {
                controller.abort();
            } catch (e) {
                // ignore
            }
            return;
        }
        res.setEncoding('binary');
        console.log(`Starting receiving of data...: ${JSON.stringify(res.headers)}`);

        res.on('data', (chunk: string) => {
            const chunkBuffer = Buffer.from(chunk, 'binary');
            console.log(`Received ${chunkBuffer.length}`);
            // add data to buffer
            context.buffer = context.buffer ? Buffer.concat([context.buffer, chunkBuffer]) : chunkBuffer;

            // if the header of PCAP file is not written yet
            if (!first) {
                // check if we have at least 6 * 4 bytes
                if (context.buffer.length > 6 * 4) {
                    first = true;
                    if (debug) {
                        const magic = context.buffer.readUInt32LE(0);
                        const versionMajor = context.buffer.readUInt16LE(4);
                        const versionMinor = context.buffer.readUInt16LE(4 + 2);
                        const reserved1 = context.buffer.readUInt32LE(4 * 2);
                        const reserved2 = context.buffer.readUInt32LE(4 * 3);
                        const snapLen = context.buffer.readUInt32LE(4 * 4);
                        const network = context.buffer.readUInt32LE(4 * 5);
                        console.log(`PCAP: ${magic.toString(16)} ${versionMajor}.${versionMinor} res1=${reserved1} res2=${reserved2} snaplen=${snapLen} ${network.toString(16)}`);
                    }

                    context.buffer = context.buffer.subarray(6 * 4);
                } else {
                    // wait for more data
                    return;
                }
            }

            let more = false;
            do {
                try {
                    more = analyzePacket(context);
                } catch (e) {
                    try {
                        controller.abort();
                    } catch {
                        // ignore
                    }
                    executeOnEnd(e);
                    return;
                }
            } while (more);

            informProgress();

            if (context?.terminate) {
                try {
                    controller.abort();
                } catch {
                    // ignore
                }
                executeOnEnd(null);
                return;
            }
        });

        res.on('end', () => executeOnEnd(null));

        res.on('error', (error: Error) => {
            try {
                controller.abort();
            } catch {
                // ignore
            }
            executeOnEnd(error);
        });
    });

    req.on('error', error => executeOnEnd(error));

    req.end();
}

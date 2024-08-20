import http from 'node:http';
import axios from 'axios';

export type Context = {
    terminate: boolean;
    controller: AbortController | null,
    packets: Buffer[];
    totalBytes: number;
    totalPackets: number;
    buffer?: Buffer;
    modifiedMagic: boolean;
    networkType: number;
    lastSaved: number;
};

export const MAX_PACKET_LENGTH = 96;
const debug = false;
const NO_FILTER = false;

function analyzePacket(context: Context): boolean {
    if (!context.buffer) {
        return false;
    }
    const len = context.buffer.byteLength || 0;
    // first 4 bytes are timestamp in seconds
    // next 4 bytes are timestamp in microseconds
    // next 4 bytes are packet length saved in file
    // next 4 bytes are packet length sent over the network
    // by modified
    // next 4 bytes ifindex
    // next 2 bytes is protocol
    // next byte is pkt_type: broadcast/multicast/etc. indication
    // next byte is padding
    const headerLength = context.modifiedMagic ? 24 : 16;

    if (len < headerLength) {
        return false;
    }

    if (debug) {
        const seconds = context.buffer.readUInt32LE(0);
        const microseconds = context.buffer.readUInt32LE(4);
        const packageLen = context.buffer.readUInt32LE(8);
        const packageLenSent = context.buffer.readUInt32LE(12);
        let MAC1;
        let MAC2;
        if (context.networkType === 0x69) {
            MAC1 = context.buffer.subarray(headerLength + 4, headerLength + 4 + 6);
            MAC2 = context.buffer.subarray(headerLength + 4 + 6, headerLength + 4 + 12);
        } else {
            MAC1 = context.buffer.subarray(headerLength, headerLength + 6);
            MAC2 = context.buffer.subarray(headerLength + 6, headerLength + 12);
        }
        console.log(`Packet: ${new Date(seconds * 1000 + Math.round(microseconds / 1000)).toISOString()} ${packageLen} ${packageLenSent} ${MAC1.toString('hex')} => ${MAC2.toString('hex')}`);
    }

    const nextPackageLen = context.buffer.readUInt32LE(8);
    if (nextPackageLen > 10000) {
        // error of capturing
        throw new Error(`Packet length is too big: ${nextPackageLen}`);
    }

    if (len < headerLength + nextPackageLen) {
        return false;
    }

    // next 6 bytes are MAC address of a source
    // next 6 bytes are MAC address of destination
    let offset = headerLength + 12;
    let maxBytes = 0;

    if (offset + 2 <= len) {
        // next 2 bytes are Ethernet type
        const ethType = context.buffer.readUInt16BE(offset);
        const ethTypeModified = offset + 20 <= len ? context.buffer.readUInt16BE(offset + 18) : 0;

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
        } else if (ethTypeModified === 0x0800) {
            maxBytes = 20 + 14 + 18; // 20 bytes of IP header + 14 bytes of Ethernet header
            // read protocol type
            const protocolType = context.buffer[offset + 11 + 18];
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
    }

    if (maxBytes) {
        if (nextPackageLen < maxBytes) {
            // remove from buffer nextPackageLen + 16 bytes
            context.packets.push(context.buffer.subarray(0, headerLength + nextPackageLen));
            context.totalBytes += headerLength + nextPackageLen;
            if (debug) {
                console.log(`Saved packet: ${headerLength + nextPackageLen}`);
            }
        } else {
            const packet = context.buffer.subarray(0, headerLength + maxBytes);
            // save new length in the packet
            packet.writeUInt32LE(maxBytes, 8);
            context.packets.push(packet);
            context.totalBytes += headerLength + maxBytes;
            if (debug) {
                console.log(`Saved packet: ${headerLength + maxBytes}`);
            }
        }
        context.totalPackets++;
    }

    // remove this packet
    context.buffer = context.buffer.subarray(headerLength + nextPackageLen);

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

export function getRecordURL(
    ip: string,
    sid: string,
    iface: string,
    MACs: string[],
) {
    const filter = MACs.length ?`ether host ${MACs.join(' || ')}` : '';

    return `http://${ip.trim()}/cgi-bin/capture_notimeout?ifaceorminor=${encodeURIComponent(iface.trim())}&snaplen=${MAX_PACKET_LENGTH}${filter ? `&filter=${encodeURIComponent(filter)}` : ''}&capture=Start&sid=${sid}`;
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
    const captureUrl = getRecordURL(ip, sid, iface, MACs);

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
        if (debug) {
            console.log(`FINISH receiving of data...: ${error}`);
        }
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

        if (debug) {
            console.log(`Starting receiving of data...: ${JSON.stringify(res.headers)}`);
        }

        informProgress();

        res.on('data', (chunk: string) => {
            const chunkBuffer = Buffer.from(chunk, 'binary');
            if (debug) {
                console.log(`Received ${chunkBuffer.length} bytes`);
            }
            // add data to buffer
            context.buffer = context.buffer ? Buffer.concat([context.buffer, chunkBuffer]) : chunkBuffer;

            if (!NO_FILTER) {
                // if the header of PCAP file is not written yet
                if (!first) {
                    // check if we have at least 6 * 4 bytes
                    if (context.buffer.length > 6 * 4) {
                        first = true;
                        const magic = context.buffer.readUInt32LE(0);
                        context.modifiedMagic = magic === 0xa1b2cd34;
                        context.networkType = context.buffer.readUInt32LE(4 * 5);

                        if (debug) {
                            const versionMajor = context.buffer.readUInt16LE(4);
                            const versionMinor = context.buffer.readUInt16LE(4 + 2);
                            const reserved1 = context.buffer.readUInt32LE(4 * 2);
                            const reserved2 = context.buffer.readUInt32LE(4 * 3);
                            const snapLen = context.buffer.readUInt32LE(4 * 4);
                            console.log(`PCAP: ${magic.toString(16)} ${versionMajor}.${versionMinor} res1=${reserved1} res2=${reserved2} snaplen=${snapLen} ${context.networkType.toString(16)}`);
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
            } else {
                // just save all data to file
                context.packets.push(chunkBuffer);
                context.totalPackets++;
                context.totalBytes += chunkBuffer.length;
            }

            informProgress();

            if (context?.terminate) {
                try {
                    controller.abort();
                } catch {
                    // ignore
                }
                executeOnEnd(null);
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

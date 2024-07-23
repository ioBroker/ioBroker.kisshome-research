import { URL } from 'node:url';
import http from 'node:http';

export type Context = {
    terminate: boolean;
    controller: AbortController | null,
    packets: Buffer[];
    totalBytes: number;
    totalPackets: number;
    buffer?: Buffer;
};

export const MAX_PACKET_LENGTH = 68;

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

    const nextPackageLen = context.buffer.readUInt32BE(8);

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
        maxBytes = 20;
        // TODO: TCP and UDP
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
        } else {
            const packet = context.buffer.subarray(0, 16 + maxBytes);
            // save new length in the packet
            packet.writeUInt32BE(maxBytes, 8);
            context.packets.push(packet);
            context.totalBytes += 16 + maxBytes;
        }
        context.totalPackets++;
    }

    // remove this packet
    context.buffer = context.buffer.subarray(16 + nextPackageLen);

    return true;
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
    const filter = `ether host ${MACs.join(' || ')}`;

    const captureUrl = `http://${ip}/cgi-bin/capture_notimeout?ifaceorminor=${iface}&snaplen=${MAX_PACKET_LENGTH}&filter=${filter}&capture=Start&sid=${sid}`;

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
        timeout && clearTimeout(timeout);
        timeout = null;
        onEnd && onEnd(error);
        onEnd = null;
    }

    // parse URL address
    const parsed = new URL(captureUrl);

    const controller = context.controller || new AbortController();
    context.controller = controller;

    const req = http.request({
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
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

        res.on('data', (chunk: Buffer) => {
            // add data to buffer
            context.buffer = context.buffer ? Buffer.concat([context.buffer, chunk]) : chunk;
            console.log(chunk.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase());

            // if the header of PCAP file is not written yet
            if (!first) {
                // check if we have at least 6 bytes
                if (context.buffer.length > 6) {
                    first = true;
                    // // write first 6 bytes to PCAP file
                    // fs.writeFileSync(targetFile, context.buffer.subarray(0, 6));
                    context.buffer = context.buffer.subarray(6);
                }
                return;
            }

            let more = false;
            do {
                more = analyzePacket(context);
            } while (more);

            informProgress();

            if (context?.terminate) {
                controller.abort()
                executeOnEnd(null);
                return;
            }
        });

        res.on('end', () => executeOnEnd(null));

        res.on('error', (error: Error) => executeOnEnd(error));
    });

    req.on('error', error => executeOnEnd(error));
}

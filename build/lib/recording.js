"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_PACKET_LENGTH = void 0;
exports.stopAllRecordingsOnFritzBox = stopAllRecordingsOnFritzBox;
exports.getRecordURL = getRecordURL;
exports.startRecordingOnFritzBox = startRecordingOnFritzBox;
const node_http_1 = __importDefault(require("node:http"));
const axios_1 = __importDefault(require("axios"));
exports.MAX_PACKET_LENGTH = 96;
const debug = false;
const NO_FILTER = false;
function analyzePacket(context) {
    if (!context.buffer) {
        return false;
    }
    const len = context.buffer.byteLength || 0;
    // Normal header is 16 bytes
    // modifiedMagic is true if the header is in Little-Endian format, and extended packet header (8 bytes more)
    // libpCapFormat is true if the header is in Big-Endian format and extended packet header (8 bytes more)
    // first 4 bytes are timestamp in seconds
    // next 4 bytes are timestamp in microseconds
    // next 4 bytes are packet length saved in file
    // next 4 bytes are packet length sent over the network
    // by modified
    // next 4 bytes ifindex
    // next 2 bytes is protocol
    // next byte is pkt_type: broadcast/multicast/etc. indication
    // next byte is padding
    const headerLength = context.libpCapFormat || context.modifiedMagic ? 24 : 16;
    if (len < headerLength) {
        return false;
    }
    const seconds = context.libpCapFormat ? context.buffer.readUInt32BE(0) : context.buffer.readUInt32LE(0);
    const microseconds = context.libpCapFormat ? context.buffer.readUInt32BE(4) : context.buffer.readUInt32LE(4);
    const packageLen = context.libpCapFormat ? context.buffer.readUInt32BE(8) : context.buffer.readUInt32LE(8);
    const packageLenSent = context.libpCapFormat ? context.buffer.readUInt32BE(12) : context.buffer.readUInt32LE(12);
    if (debug) {
        let MAC1;
        let MAC2;
        if (context.networkType === 0x69) {
            MAC1 = context.buffer.subarray(headerLength + 4, headerLength + 4 + 6);
            MAC2 = context.buffer.subarray(headerLength + 4 + 6, headerLength + 4 + 12);
        }
        else {
            MAC1 = context.buffer.subarray(headerLength, headerLength + 6);
            MAC2 = context.buffer.subarray(headerLength + 6, headerLength + 12);
        }
        console.log(`Packet: ${new Date(seconds * 1000 + Math.round(microseconds / 1000)).toISOString()} ${packageLen} ${packageLenSent} ${MAC1.toString('hex')} => ${MAC2.toString('hex')}`);
    }
    if (packageLen > 10000) {
        // error of capturing
        throw new Error(`Packet length is too big: ${packageLen}`);
    }
    if (len < headerLength + packageLen) {
        return false;
    }
    // next 6 bytes are MAC address of a source
    // next 6 bytes are MAC address of destination
    const offset = headerLength + 12;
    let maxBytes = 0;
    if (offset + 2 <= len) {
        // next 2 bytes are Ethernet type
        const ethType = context.buffer.readUInt16BE(offset);
        // If IPv4
        if (ethType === 0x0800) {
            const ipHeaderStart = offset + 2;
            const ipVersionAndIHL = context.buffer[ipHeaderStart];
            const ipHeaderLength = (ipVersionAndIHL & 0x0f) * 4; // IHL field gives the length of the IP header
            // read protocol type (TCP/UDP/ICMP/etc.)
            const protocolType = context.buffer[ipHeaderStart + 9]; // Protocol field in IP header
            if (protocolType === 6) {
                // TCP
                const tcpHeaderStart = ipHeaderStart + ipHeaderLength;
                const tcpOffsetAndFlags = context.buffer[tcpHeaderStart + 12];
                const tcpHeaderLength = (tcpOffsetAndFlags >> 4) * 4; // Data offset in TCP header
                maxBytes = ipHeaderLength + tcpHeaderLength + 14; // Total length: IP header + TCP header + Ethernet header
            }
            else if (protocolType === 17) {
                // UDP
                maxBytes = ipHeaderLength + 8 + 14; // IP header + 8 bytes UDP header + Ethernet header
            }
            else {
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
        if (packageLen < maxBytes) {
            // remove from buffer packageLen + 16 bytes
            const packetBuffer = context.buffer.subarray(0, headerLength + packageLen);
            if (context.libpCapFormat) {
                // write header in LE notation
                packetBuffer.writeUInt32LE(seconds, 0);
                packetBuffer.writeUInt32LE(microseconds, 4);
                packetBuffer.writeUInt32LE(packageLen, 8);
                packetBuffer.writeUInt32LE(packageLenSent, 12);
                const ifindex = packetBuffer.readUInt32BE(16);
                const protocol = packetBuffer.readUInt16BE(20);
                packetBuffer.writeUInt32LE(ifindex, 16);
                packetBuffer.writeUInt16LE(protocol, 20);
            }
            context.packets.push(packetBuffer);
            context.totalBytes += headerLength + packageLen;
            if (debug) {
                console.log(`Saved packet: ${headerLength + packageLen}`);
            }
        }
        else {
            const packetBuffer = context.buffer.subarray(0, headerLength + maxBytes);
            if (context.libpCapFormat) {
                // write header in LE notation
                packetBuffer.writeUInt32LE(seconds, 0);
                packetBuffer.writeUInt32LE(microseconds, 4);
                packetBuffer.writeUInt32LE(packageLenSent, 12);
                const ifindex = packetBuffer.readUInt32BE(16);
                const protocol = packetBuffer.readUInt16BE(20);
                packetBuffer.writeUInt32LE(ifindex, 16);
                packetBuffer.writeUInt16LE(protocol, 20);
            }
            // save new length in the packet
            packetBuffer.writeUInt32LE(maxBytes, 8);
            context.packets.push(packetBuffer);
            context.totalBytes += headerLength + maxBytes;
            if (debug) {
                console.log(`Saved packet: ${headerLength + maxBytes}`);
            }
        }
        context.totalPackets++;
    }
    // remove this packet
    context.buffer = context.buffer.subarray(headerLength + packageLen);
    return true;
}
async function stopAllRecordingsOnFritzBox(ip, sid) {
    const captureUrl = `http://${ip.trim()}/cgi-bin/capture_notimeout?iface=stopall&capture=Stop&sid=${sid}`;
    const response = await axios_1.default.get(captureUrl);
    return response.data;
}
function getRecordURL(ip, sid, iface, MACs) {
    const filter = MACs.filter(m => m === null || m === void 0 ? void 0 : m.trim()).length ? `ether host ${MACs.filter(m => m === null || m === void 0 ? void 0 : m.trim()).join(' || ')}` : '';
    return `http://${ip.trim()}/cgi-bin/capture_notimeout?ifaceorminor=${encodeURIComponent(iface.trim())}&snaplen=${exports.MAX_PACKET_LENGTH}${filter ? `&filter=${encodeURIComponent(filter)}` : ''}&capture=Start&sid=${sid}`;
}
function startRecordingOnFritzBox(ip, sid, iface, MACs, onEnd, context, progress, log) {
    const captureUrl = getRecordURL(ip, sid, iface, MACs);
    let first = false;
    context.buffer = Buffer.from([]);
    let timeout = null;
    let lastProgress = Date.now();
    const informProgress = () => {
        const now = Date.now();
        if (now - lastProgress > 1000) {
            lastProgress = now;
            progress && progress();
        }
    };
    const executeOnEnd = (error) => {
        if (debug) {
            console.log(`FINISH receiving of data...: ${error === null || error === void 0 ? void 0 : error.toString()}`);
        }
        timeout && clearTimeout(timeout);
        timeout = null;
        onEnd && onEnd(error);
        onEnd = null;
    };
    const controller = context.controller || new AbortController();
    context.controller = controller;
    context.started = Date.now();
    console.log(`START capture: ${captureUrl}`);
    const req = node_http_1.default.request(captureUrl, {
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
            }
            catch {
                // ignore
            }
            return;
        }
        res.setEncoding('binary');
        if (debug && log) {
            log(`Starting receiving of data...: ${JSON.stringify(res.headers)}`, 'debug');
        }
        informProgress();
        res.on('data', (chunk) => {
            const chunkBuffer = Buffer.from(chunk, 'binary');
            if (debug && log) {
                log(`Received ${chunkBuffer.length} bytes`, 'debug');
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
                        context.libpCapFormat = magic === 0x34cdb2a1;
                        const versionMajor = context.libpCapFormat
                            ? context.buffer.readUInt16BE(4)
                            : context.buffer.readUInt16LE(4);
                        const versionMinor = context.libpCapFormat
                            ? context.buffer.readUInt16BE(4 + 2)
                            : context.buffer.readUInt16LE(4 + 2);
                        const reserved1 = context.libpCapFormat
                            ? context.buffer.readUInt32BE(4 * 2)
                            : context.buffer.readUInt32LE(4 * 2);
                        const reserved2 = context.libpCapFormat
                            ? context.buffer.readUInt32BE(4 * 3)
                            : context.buffer.readUInt32LE(4 * 3);
                        const snapLen = context.libpCapFormat
                            ? context.buffer.readUInt32BE(4 * 4)
                            : context.buffer.readUInt32LE(4 * 4);
                        context.networkType = context.libpCapFormat
                            ? context.buffer.readUInt32BE(4 * 5)
                            : context.buffer.readUInt32LE(4 * 5);
                        if (debug) {
                            console.log(`PCAP: ${magic.toString(16)} v${versionMajor}.${versionMinor} res1=${reserved1} res2=${reserved2} snaplen=${snapLen} network=${context.networkType.toString(16)}`);
                        }
                        // remove header
                        context.buffer = context.buffer.subarray(6 * 4);
                    }
                    else {
                        // wait for more data
                        return;
                    }
                }
                let more = false;
                do {
                    try {
                        more = analyzePacket(context);
                    }
                    catch (e) {
                        try {
                            controller.abort();
                        }
                        catch {
                            // ignore
                        }
                        executeOnEnd(e);
                        return;
                    }
                } while (more);
            }
            else {
                // just save all data to file
                context.packets.push(chunkBuffer);
                context.totalPackets++;
                context.totalBytes += chunkBuffer.length;
            }
            informProgress();
            if (context === null || context === void 0 ? void 0 : context.terminate) {
                try {
                    controller.abort();
                }
                catch {
                    // ignore
                }
                executeOnEnd(null);
            }
        });
        res.on('end', () => {
            if (log) {
                log(`File closed by fritzbox after ${context.totalBytes} bytes received in ${Math.floor((Date.now() - context.started) / 100) / 10} seconds`, 'debug');
            }
            if (!context.totalBytes && log && Date.now() - context.started < 3000) {
                log(`No bytes received and file was closed by Fritzbox very fast. May be wrong interface selected`, 'info');
                log(`Keine Bytes empfangen und Datei wurde von Fritzbox sehr schnell geschlossen. Möglicherweise falsche Schnittstelle ausgewählt`, 'info');
            }
            executeOnEnd(null);
        });
        res.on('error', (error) => {
            if (!error && log) {
                log(`Error by receiving, but no error provided!`, 'error');
            }
            try {
                controller.abort();
            }
            catch {
                // ignore
            }
            executeOnEnd(error);
        });
    });
    req.on('error', error => executeOnEnd(error));
    req.end();
}
//# sourceMappingURL=recording.js.map
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMacForIp = getMacForIp;
exports.validateIpAddress = validateIpAddress;
exports.getVendorForMac = getVendorForMac;
exports.getDefaultGateway = getDefaultGateway;
exports.generateKeys = generateKeys;
// @ts-expect-error no types
const network_1 = require("network");
const arp_lookup_1 = require("@network-utils/arp-lookup");
const vendor_lookup_1 = require("@network-utils/vendor-lookup");
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_net_1 = require("node:net");
// This function is used trigger the OS to resolve IP to MAC address
async function httpPing(ip) {
    // try to open the TCP socket to this IP
    const client = new node_net_1.Socket();
    return await new Promise(resolve => {
        let timeout = setTimeout(() => {
            timeout = null;
            resolve(false);
        }, 200);
        client.connect(18001, ip, () => {
            client.destroy();
            if (timeout) {
                clearTimeout(timeout);
                timeout = null;
                resolve(true);
            }
        });
        client.on('error', () => {
            client.destroy();
            if (timeout) {
                clearTimeout(timeout);
                timeout = null;
                resolve(false);
            }
        });
    });
}
async function getMacForIp(ip) {
    // trigger the OS to resolve IP to MAC address
    await httpPing(ip);
    const mac = await (0, arp_lookup_1.toMAC)(ip);
    if (mac) {
        return { mac: mac.toUpperCase(), vendor: (0, vendor_lookup_1.toVendor)(mac), ip };
    }
    return null;
}
function validateIpAddress(ip) {
    if (!ip) {
        return true;
    }
    if (typeof ip !== 'string') {
        return false;
    }
    ip = ip.trim();
    if (!ip) {
        return true;
    }
    if (!ip.match(/^\d+\.\d+\.\d+\.\d+$/)) {
        return false;
    }
    const parts = ip
        .trim()
        .split('.')
        .map(part => parseInt(part, 10));
    return !parts.find(part => part < 0 || part > 0xff);
}
function getVendorForMac(mac) {
    return (0, vendor_lookup_1.toVendor)(mac);
}
function getDefaultGateway() {
    return new Promise((resolve, reject) => (0, network_1.get_gateway_ip)((err, ip) => {
        if (err) {
            return reject(new Error(err));
        }
        return resolve(ip);
    }));
}
function generateKeys() {
    // const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    //     modulusLength: 4096, // bits - standard for RSA keys
    //     publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    //     privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    // });
    // const sshKeyBodyPublic = publicKey.toString();
    const result = node_crypto_1.default.generateKeyPairSync('ed25519', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const privateKey = result.privateKey;
    const publicKey = result.publicKey;
    const sshKeyBodyPublic = publicKey.toString().split('\n').slice(1, -2).join('');
    return { publicKey: sshKeyBodyPublic, privateKey: privateKey.toString() };
}
//# sourceMappingURL=utils.js.map
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMacForIp = getMacForIp;
exports.getDefaultGateway = getDefaultGateway;
exports.generateKeys = generateKeys;
// @ts-expect-error no types
const network_1 = require("network");
const arp_lookup_1 = require("@network-utils/arp-lookup");
const vendor_lookup_1 = require("@network-utils/vendor-lookup");
const node_crypto_1 = __importDefault(require("node:crypto"));
async function getMacForIp(ip) {
    const mac = await (0, arp_lookup_1.toMAC)(ip);
    if (mac) {
        return { mac: mac.toUpperCase(), vendor: (0, vendor_lookup_1.toVendor)(mac), ip };
    }
    return null;
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
    const sshKeyBodyPublic = publicKey.export().toString().split('\n').slice(1, -2).join('');
    return { publicKey: sshKeyBodyPublic, privateKey: privateKey.export().toString() };
}
//# sourceMappingURL=utils.js.map
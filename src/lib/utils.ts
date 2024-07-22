// @ts-expect-error no types
import { get_gateway_ip } from 'network';
import { toMAC } from '@network-utils/arp-lookup';
import { toVendor } from '@network-utils/vendor-lookup';
import crypto from 'node:crypto';
import { exec } from "node:child_process";

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

export function generateKeys(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    return { publicKey, privateKey };
}

export function getRsyncPath(): Promise<string> {
    return new Promise(resolve => {
        if (process.platform === 'win32') {
            resolve('rsync');
            return;
        }

        exec('which rsync', (error, stdout, stderr) => {
            if (error) {
                resolve('/usr/bin/rsync');
            }
            resolve(stdout.trim());
        })
    });
}

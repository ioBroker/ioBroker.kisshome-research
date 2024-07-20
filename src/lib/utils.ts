// @ts-expect-error no types
import { get_gateway_ip } from 'network';
import { toMAC } from '@network-utils/arp-lookup';
import { toVendor } from '@network-utils/vendor-lookup'

export async function getMacForIp(ip: string): Promise<{ mac: string; vendor?: string } | null> {
    const mac = await toMAC(ip);
    if (mac) {
        return { mac, vendor: toVendor(mac) };
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

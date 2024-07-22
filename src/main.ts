import * as utils from '@iobroker/adapter-core';
import fs from 'node:fs';
import { getDefaultGateway, getMacForIp } from './lib/utils';

type KISSHomeResearchConfig = {
    /** Fritzbox IP address */
    fritzbox: string;
    /** Fritzbox login */
    login: string;
    /** Fritzbox password */
    password: string;
    /** Working directory */
    tempDir: string;
    /** Fritzbox interface */
    iface: string;
    customIPs: {
        mac: string;
        ip: string;
        description: string;
    }[];
    instanceIPs: {
        mac: string;
        ip: string;
        description: string;
    }[];
}

export class KISSHomeResearchAdapter extends utils.Adapter {
    protected tempDir: string = '';

    public constructor(options: Partial<utils.AdapterOptions> = {}) {
        super({
            ...options,
            name: 'kisshome-research',
        });
        this.on('ready', () => this.onReady());
        this.on('stateChange', (id, state) => this.onStateChange(id, state));
        this.on('objectChange', (id /* , object */) => this.onObjectChange(id));
        this.on('unload', callback => this.onUnload(callback));
        this.on('message', this.onMessage.bind(this));
    }

    async onMessage(msg: ioBroker.Message): Promise<void> {
        if (typeof msg === 'object' && msg.message) {
            switch (msg.command) {
                case 'getDefaultGateway':
                    if (msg.callback) {
                        try {
                            const ip = await getDefaultGateway();
                            this.sendTo(msg.from, msg.command, {result: ip}, msg.callback);
                        } catch (e) {
                            this.sendTo(msg.from, msg.command, {error: e.message}, msg.callback);
                        }
                    }
                    break;

                case 'getMacForIps':
                    if (msg.callback) {
                        try {
                            const result = await KISSHomeResearchAdapter.getMacForIps(msg.message.ips);
                            this.sendTo(msg.from, msg.command, { result }, msg.callback);
                        } catch (e) {
                            this.sendTo(msg.from, msg.command, { error: e.message }, msg.callback);
                        }
                    }
                    break;
            }
        }
    }

    async onReady(): Promise<void> {
        const config: KISSHomeResearchConfig = this.config as unknown as KISSHomeResearchConfig;
        // first, try to detect the default gateway
        if (config.fritzbox === '0.0.0.0') {
            try {
                const ip = await getDefaultGateway();
                if (ip && ip !== '0.0.0.0') {
                    this.log.info(`Found default gateway: ${ip}`);
                    config.fritzbox = ip;
                    const obj = await this.getForeignObjectAsync(`system.adapter.${this.namespace}`);
                    if (obj) {
                        obj.native.fritzbox = ip;
                        await this.setForeignObjectAsync(obj._id, obj);
                        // wait for restart
                        return;
                    }
                }
            } catch (e) {
                this.log.warn(`Cannot get default gateway: ${e}`);
            }
        }

        // try to get MAC addresses for all IPs
        const IPs = [...config.customIPs, ...config.instanceIPs];
        const tasks = IPs.filter(ip => !ip.mac);
        if (tasks.length) {
            try {
                const macs = await KISSHomeResearchAdapter.getMacForIps(tasks.map(t => t.ip));
                for (let i = 0; i < tasks.length; i++) {
                    const mac = macs[i];
                    if (mac?.mac) {
                        const item = IPs.find(t => t.ip === mac.ip);
                        if (item) {
                            item.mac = mac.mac;
                        }
                    }
                }
            } catch (e: unknown) {
                this.log.error(`Cannot get MAC addresses: ${e}`);
            }
        }

        // detect temp directory
        this.tempDir = config.tempDir || '/run/shm';
        if (fs.existsSync(this.tempDir)) {
            this.log.info(`Using ${this.tempDir} as temporary directory`);
        } else if (fs.existsSync('/run/shm')) {
            this.tempDir = '/run/shm';
            this.log.info(`Using ${this.tempDir} as temporary directory`);
        } else if (fs.existsSync('/tmp')) {
            this.tempDir = '/tmp';
            this.log.info(`Using ${this.tempDir} as temporary directory`);
        } else {
            this.log.warn(`Cannot find any temporary directory. Please specify manually in the configuration. For best performance it should be a RAM disk`);
            return this.terminate(11);
        }

        this.saveMetaFile(IPs);
    }

    saveMetaFile(IPs: { mac: string; ip: string; description: string }[]): void {
        const text = KISSHomeResearchAdapter.getDescriptionFile(IPs);
        const now = new Date();
        fs.writeFileSync(`${this.tempDir}/${now.getUTCFullYear()}-${(now.getUTCMonth() + 1).toString().padStart(2, '0')}-${now.getUTCDate().toString().padStart(2, '0')}_${now.getUTCHours().toString().padStart(2, '0')}-${now.getUTCMinutes().toString().padStart(2, '0')}-${now.getUTCSeconds().toString().padStart(2, '0')}_meta.json`, text);
    }

    static getDescriptionFile(IPs: { mac: string; ip: string; description: string }[]): string {
        const desc: Record<string, { ip: string; desc: string }>= {};
        IPs.sort((a, b) => a.ip.localeCompare(b.ip)).forEach(ip => {
            desc[ip.ip] = { ip: ip.ip, desc: ip.description };
        });
        return JSON.stringify(desc, null, 2);
    }

    static async getMacForIps(ips: string[]): Promise<{ mac: string; vendor?: string, ip: string }[]> {
        const result: { mac: string; vendor?: string, ip: string }[] = [];
        let error: string = '';
        for (let ip of ips) {
            try {
                const mac = await getMacForIp(ip);
                if (mac) {
                    result.push(mac);
                }
            } catch (e) {
                error = e.message;
            }
        }
        if (!result.length && ips.length) {
            throw new Error(error || 'no results');
        }

        return result;
    }

    async onUnload(callback: () => void): Promise<void> {
        try {
            callback();
        } catch (e) {
            callback();
        }
    }

    async onObjectChange(id: string/*, obj: ioBroker.Object | null | undefined*/): Promise<void> {

    }

    async onStateChange(id: string, state: ioBroker.State | null | undefined): Promise<void> {

    }
}

if (require.main !== module) {
    // Export the constructor in compact mode
    module.exports = (options: Partial<utils.AdapterOptions> | undefined) => new KISSHomeResearchAdapter(options);
} else {
    // otherwise start the instance directly
    (() => new KISSHomeResearchAdapter())();
}

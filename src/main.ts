import * as utils from '@iobroker/adapter-core';
import { getDefaultGateway, getMacForIp } from './lib/utils';

export class KISSHomeResearchAdapter extends utils.Adapter {
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

    }

    static async getMacForIps(ips: string[]): Promise<{ mac?: string; vendor?: string, ip: string }[]> {
        const result = [];
        let error: string = '';
        for (let ip of ips) {
            try {
                const mac = await getMacForIp(ip);
                if (result) {
                    result.push({...mac, ip});
                }
            } catch (e) {
                error = e.message;
            }
            if (!result.length && ips.length) {
                throw new Error(error || 'no results');
            }
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

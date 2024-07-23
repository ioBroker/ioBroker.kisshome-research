import * as utils from '@iobroker/adapter-core';
import fs from 'node:fs';
import axios from 'axios';
import { exec } from 'node:child_process';

import {
    getDefaultGateway, getMacForIp,
    generateKeys, getRsyncPath,
} from './lib/utils';

import { startRecordingOnFritzBox, type Context, MAX_PACKET_LENGTH } from './lib/recording';
import { getFritzBoxToken } from './lib/fritzbox';

const PCAP_HOST = 'kisshome-experiments.if-is.net';
// key of the kisshome-experiments.if-is.net host
const SSH_KNOWN_KEY = 'ssh-ed25519 255 SHA256:PesPlH50RqbZUVsJ36pht255bUudtwKPcjcTCyqeel4';

type KISSHomeResearchConfig = {
    /** Registered email address */
    email: string;
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

interface KeysObject extends ioBroker.OtherObject {
    native: {
        publicKey: string;
        privateKey: string;
    };
}

export class KISSHomeResearchAdapter extends utils.Adapter {
    protected tempDir: string = '';

    private uniqueMacs: string[] = [];

    private __dirname: string = __dirname;

    private sid: string = '';

    private startTimeout: ioBroker.Timeout | undefined;

    private context: Context = {
        terminate: false,
        controller: null,
        packets: [],
        totalBytes: 0,
        totalPackets: 0,
        buffer: Buffer.from([]),
    };

    private recordingRunning: boolean = false;

    private privateKeyPath: string = '';

    private knownHostFile: string = '';

    private workingDir: string = '';

    private rsyncPath: string = '';

    private syncRunning: boolean = false;

    private saveAfterSync: boolean = false;

    private recordStarted: number = 0;

    private monitorInterval: ioBroker.Interval | undefined;

    public constructor(options: Partial<utils.AdapterOptions> = {}) {
        super({
            ...options,
            name: 'kisshome-research',
        });
        this.on('ready', () => this.onReady());
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
                            this.sendTo(msg.from, msg.command, { result: ip }, msg.callback);
                        } catch (e) {
                            this.sendTo(msg.from, msg.command, { error: e.message }, msg.callback);
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

        // remove running flag
        const runningState = await this.getStateAsync('info.connection');
        if (runningState?.val) {
            await this.setState('info.connection', false, true);
        }

        const captured = await this.getStateAsync('info.capturedPackets');
        if (captured?.val) {
            await this.setState('info.capturedPackets', 0, true);
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

        // take only unique MAC addresses
        this.uniqueMacs = [];
        IPs.forEach(item => !this.uniqueMacs.includes(item.mac) && this.uniqueMacs.push(item.mac));

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

        this.tempDir = this.tempDir.replace(/\\/g, '/');

        if (this.tempDir.endsWith('/')) {
            this.tempDir = this.tempDir.substring(0, this.tempDir.length - 1);
        }

        this.clearWorkingDir();

        let privateKey: string;
        let publicKey: string;

        // retrieve public and private keys
        let keysObj: KeysObject | null;
        try {
            keysObj = await this.getObjectAsync('info.keys') as KeysObject;
        } catch (e) {
            // ignore
            keysObj = null;
        }
        if (!keysObj || !keysObj.native?.publicKey || !keysObj.native?.privateKey) {
            this.log.info('Generating keys for first time');
            const result = generateKeys();
            privateKey = result.privateKey;
            publicKey = result.publicKey;

            keysObj = {
                _id: 'info.keys',
                type: 'config',
                common: {
                    name: {
                        en: 'Public and private keys',
                        de: 'Öffentliche und private Schlüssel',
                        ru: 'Публичные и частные ключи',
                        pt: 'Chaves públicas e privadas',
                        nl: 'Openbare en privésleutels',
                        fr: 'Clés publiques et privées',
                        it: 'Chiavi pubbliche e private',
                        es: 'Claves públicas y privadas',
                        pl: 'Klucze publiczne i prywatne',
                        uk: 'Публічні та приватні ключі',
                        'zh-cn': '公钥和私钥'
                    }
                },
                native: {
                    publicKey,
                    privateKey,
                },
            };
            await this.setObjectAsync(keysObj._id, keysObj);
        } else {
            privateKey = keysObj.native.privateKey;
            publicKey = keysObj.native.publicKey;
        }

        if (!publicKey || !privateKey) {
            this.log.error('Cannot generate keys');
            return;
        }

        this.workingDir = `${this.tempDir}/hourly_pcaps`;

        // create hourly directory
        try {
            if (!fs.existsSync(this.workingDir)) {
                fs.mkdirSync(this.workingDir);
            }
        } catch (e) {
            this.log.error(`Cannot create working directory: ${e}`);
            return;
        }

        // update privateKey on disk
        this.privateKeyPath = `${this.__dirname}/privateKey.pem`.replace(/\\/g, '/');
        if (fs.existsSync(this.privateKeyPath)) {
            const oldPrivateKey = fs.readFileSync(this.privateKeyPath, 'utf8');
            if (oldPrivateKey !== privateKey) {
                this.log.warn('Private key changed. Updating...');
                fs.writeFileSync(this.privateKeyPath, privateKey);
            }
        } else {
            fs.writeFileSync(this.privateKeyPath, privateKey);
        }

        // update known_hosts file
        this.knownHostFile = `${this.__dirname}/kisshome_known_hosts`.replace(/\\/g, '/');

        // create home known file
        const text = `${PCAP_HOST} ${SSH_KNOWN_KEY}`;
        if (!fs.existsSync(this.knownHostFile)) {
            this.log.debug(`Creating known_hosts file: ${this.knownHostFile}`);
            fs.writeFileSync(this.knownHostFile, text);
        } else if (fs.readFileSync(this.knownHostFile).toString('utf8') !== text) {
            this.log.warn(`Updating known_hosts file: ${this.knownHostFile}`);
            fs.appendFileSync(this.knownHostFile, text);
        }

        if (!config.email) {
            this.log.error('No email provided. Please provide an email address in the configuration');
            this.log.error('You must register this email first on https://kisshome-feldversuch.if-is.net/#register');
            return;
        }
        try {
            // register on the cloud
            const response = await axios.post(`https://${PCAP_HOST}/api/v1/registerKey/${config.email}`, {
                publicKey,
            });
            if (response.status === 200) {
                this.log.info('Successfully registered on the cloud');
            } else {
                if (response.status === 404) {
                    this.log.error(`Cannot register on the cloud: unknown email address`);
                } else if (response.status === 403) {
                    this.log.error(`Cannot register on the cloud: public key changed`);
                } else {
                    this.log.error(`Cannot register on the cloud: ${response.data || response.statusText || response.status}`);
                }
                return;
            }
        } catch (e) {
            this.log.error(`Cannot register on the cloud: ${e}`);
            return;
        }

        // get rsync path
        try {
            this.rsyncPath = await getRsyncPath();
        } catch (e) {
            this.log.error(`Cannot get rsync path: ${e}`);
            return;
        }

        this.saveMetaFile(IPs);

        // start the monitoring
        this.startRecording(config)
            .catch(e => this.log.error(`Cannot start recording: ${e}`));
    }

    restartRecording(config: KISSHomeResearchConfig): void {
        this.startTimeout && clearTimeout(this.startTimeout);
        this.startTimeout = this.setTimeout(() => {
            this.startTimeout = undefined;
            this.startRecording(config)
                .catch(e => this.log.error(`Cannot start recording: ${e}`));
        }, 10000);
    }

    savePacketsToFile(){
        if (this.context.packets.length) {
            const packetsToSave = this.context.packets;
            this.context.packets = [];

            const fileName = `${this.tempDir}/${KISSHomeResearchAdapter.getTimestamp()}.pcap`;
            // create PCAP header
            const byteArray = Buffer.alloc(6 * 4);
            // magic number
            byteArray.writeUInt32LE(0xa1b2c3d4, 0);
            // major version
            byteArray.writeUInt16LE(2, 4);
            // minor version
            byteArray.writeUInt16LE(4, 6);
            // reserved
            byteArray.writeUInt32LE(0, 8);
            // reserved
            byteArray.writeUInt32LE(0, 12);
            // SnapLen
            byteArray.writeUInt16LE(MAX_PACKET_LENGTH, 16);
            // network type
            byteArray.writeUInt32LE(1, 24);

            // get file descriptor of file
            const fd = fs.openSync(fileName, 'w');
            // write header
            fs.writeSync(fd, byteArray, 0, byteArray.length, 0);
            for (let i = 0; i < packetsToSave.length; i++) {
                const packet = packetsToSave[i];
                const packetBuffer = Buffer.from(packet);
                fs.writeSync(fd, packetBuffer, 0, packetBuffer.length, 24 + i * packetBuffer.length);
            }
            fs.closeSync(fd);
        }
    }

    async startRecording(config: KISSHomeResearchConfig) {
        // take sid from fritzbox
        if (!this.sid) {
            try {
                this.sid = await getFritzBoxToken(config.fritzbox, config.login, config.password);
            } catch (e) {
                this.log.error(`Cannot get SID from FritzBox: ${e}`);
            }
        }

        if (this.sid) {
            const captured = await this.getStateAsync('info.capturedPackets');
            if (captured?.val) {
                await this.setState('info.capturedPackets', 0, true);
            }

            this.context.controller = new AbortController();

            this.context.packets = [];
            this.context.totalBytes = 0;
            this.context.totalPackets = 0;

            this.recordStarted = Date.now();

            startRecordingOnFritzBox(
                config.fritzbox,
                this.sid,
                config.iface,
                this.uniqueMacs,
                (error: Error | null) => {
                    this.monitorInterval && this.clearInterval(this.monitorInterval);
                    this.monitorInterval = undefined;

                    this.savePacketsToFile();

                    this.context.totalBytes = 0;
                    this.context.totalPackets = 0;

                    if (error?.message === 'Unauthorized') {
                        this.sid = '';
                    }

                    if (this.recordingRunning) {
                        this.log.info(`Recording stopped`);
                        this.recordingRunning = false;
                        this.setState('info.connection', false, true);
                    }

                    if (this.context.packets?.length) {
                        this.setState('info.capturedPackets', this.context.totalPackets, true);
                    }

                    error && this.log.error(`Error while recording: ${error}`);
                    if (!this.context.terminate) {
                        this.restartRecording(config);
                    }
                },
                this.context,
                () => {
                    if (!this.recordingRunning) {
                        this.recordingRunning = true;
                        this.setState('info.connection', true, true);

                        this.monitorInterval = this.monitorInterval || this.setInterval(() => {
                            // save if file is bigger than 50 Mb
                            if (this.context.totalBytes > 50 * 1024 * 1024) {
                                if (this.syncRunning) {
                                    this.saveAfterSync = true;
                                } else {
                                    this.savePacketsToFile();
                                }
                            }

                            if (Date.now() - this.recordStarted >= 3_600_0000) {
                                this.recordStarted = Date.now();
                                this.startSynchronization();
                            }
                        }, 10000);
                    }

                    this.setState('info.capturedPackets', this.context.totalPackets, true);
                },
            );
        } else {
            // try to get the token in 10 seconds again. E.g., if fritzbox is rebooting
            this.restartRecording(config);
        }
    }

    static getTimestamp(): string {
        const now = new Date();
        return `${now.getUTCFullYear()}-${(now.getUTCMonth() + 1).toString().padStart(2, '0')}-${now.getUTCDate().toString().padStart(2, '0')}_${now.getUTCHours().toString().padStart(2, '0')}-${now.getUTCMinutes().toString().padStart(2, '0')}-${now.getUTCSeconds().toString().padStart(2, '0')}`;
    }

    saveMetaFile(IPs: { mac: string; ip: string; description: string }[]): void {
        const text = KISSHomeResearchAdapter.getDescriptionFile(IPs);
        // find the latest file
        const files = fs.readdirSync(this.workingDir);
        files.sort((a, b) => b.localeCompare(a));
        let latestFile = '';
        // find the latest file and delete all other _meta.json files
        for (const file of files) {
            if (!latestFile && file.endsWith('_meta.json')) {
                latestFile = file;
            } else if (file.endsWith('_meta.json')) {
                fs.unlinkSync(`${this.workingDir}/${file}`);
            }
        }

        // if existing meta file found
        if (latestFile) {
            // compare the content
            const oldFile = fs.readFileSync(`${this.workingDir}/${latestFile}`, 'utf8');
            if (oldFile !== text) {
                this.log.debug('Meta file updated');
                fs.unlinkSync(`${this.workingDir}/${latestFile}`);
                fs.writeFileSync(`${this.workingDir}/${KISSHomeResearchAdapter.getTimestamp()}_meta.json`, text);
            }
        } else {
            this.log.info('Meta file created');
            // if not found => create new one
            fs.writeFileSync(`${this.workingDir}/${KISSHomeResearchAdapter.getTimestamp()}_meta.json`, text);
        }
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
        if (this.recordingRunning) {
            this.recordingRunning = false;
            this.setState('info.connection', false, true);
        }
        this.startTimeout && clearTimeout(this.startTimeout);
        this.startTimeout = undefined;

        this.context.terminate = true;
        if (this.context.controller) {
            this.context.controller.abort();
            this.context.controller = null;
        }

        try {
            callback();
        } catch (e) {
            callback();
        }
    }

    clearWorkingDir() {
        try {
            const files = fs.readdirSync(this.workingDir);
            for (const file of files) {
                if (file.endsWith('.pcap')) {
                    try {
                        fs.unlinkSync(`${this.workingDir}/${file}`);
                    } catch (e) {
                        this.log.error(`Cannot delete file ${this.workingDir}/${file}: ${e}`);
                    }
                } else if (!file.endsWith('.json')) {
                    // delete unknown files
                    try {
                        fs.unlinkSync(`${this.workingDir}/${file}`);
                    } catch (e) {
                        this.log.error(`Cannot delete file ${this.workingDir}/${file}: ${e}`);
                    }
                }
            }
        } catch (e) {
            this.log.error(`Cannot read directory "${this.workingDir}": ${e}`);
        }
    }

    startSynchronization(): void {
        // calculate the total number of bytes
        let totalBytes = 0;
        if (this.syncRunning) {
            this.syncRunning = false;
            this.setState('info.syncRunning', false, true);
        }
        try {
            const files = fs.readdirSync(this.workingDir);
            for (const file of files) {
                totalBytes += fs.statSync(`${this.workingDir}/${file}`).size;
            }
        } catch (e) {
            this.log.error(`Cannot read directory "${this.workingDir}": ${e}`);
            return;
        }

        if (!totalBytes) {
            return;
        }

        this.log.debug(`Syncing files to the cloud (${Math.round(totalBytes / (1024 * 1024) * 100) / 100} Mb)`);

        this.setState('info.syncRunning', true, true);

        const cmd = [
            this.rsyncPath,
            '-avr',
            '-e',
            `"ssh -o UserKnownHostsFile=${this.knownHostFile} -i ${this.privateKeyPath}"`,
            this.workingDir,
            `pcaprecv@${PCAP_HOST}:/dummyPath/`,
        ];

        let error = '';

        if (!this.syncRunning) {
            this.syncRunning = true;
            this.setState('info.syncRunning', true, true);
        }

        const cp = exec(cmd.join(' '), (_error, stdout, stderr) => {
            (stderr || _error) && this.log.warn(`Error by synchronization: ${stderr}, ${_error}`);
            error = _error ? _error.message : '';
        });

        cp.on('error', (_error) => error = _error.message);

        cp.on('exit', (code) => {
            // delete all pcap files if no error
            if (!error && code === 0) {
                this.clearWorkingDir();
            }

            if (this.syncRunning) {
                this.syncRunning = false;
                this.setState('info.syncRunning', false, true);
            }

            if (this.saveAfterSync) {
                this.saveAfterSync = false;
                this.savePacketsToFile();
            }

            if (code !== 0) {
                this.log.warn(`Cannot sync files. rsync returned ${code}, error: ${error}`);
            } else {
                this.log.debug(`Syncing files done with code ${code}`);
            }
        });
    }
}

if (require.main !== module) {
    // Export the constructor in compact mode
    module.exports = (options: Partial<utils.AdapterOptions> | undefined) => new KISSHomeResearchAdapter(options);
} else {
    // otherwise start the instance directly
    (() => new KISSHomeResearchAdapter())();
}

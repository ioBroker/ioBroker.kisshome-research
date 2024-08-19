import * as utils from '@iobroker/adapter-core';
import fs from 'node:fs';
import axios from 'axios';
import terminate from 'terminate/promise';
import { exec, type ChildProcess } from 'node:child_process';

import {
    getDefaultGateway, getMacForIp,
    generateKeys, getRsyncPath,
} from './lib/utils';

import {
    startRecordingOnFritzBox, type Context,
    MAX_PACKET_LENGTH, stopAllRecordingsOnFritzBox,
    getRecordURL,
} from './lib/recording';
import {
    getFritzBoxInterfaces,
    getFritzBoxToken,
    getFritzBoxUsers,
} from './lib/fritzbox';

// const PCAP_HOST = 'kisshome-experiments.if-is.net';
const PCAP_HOST = 'iobroker.link:8444';
// key of the kisshome-experiments.if-is.net host
// const SSH_KNOWN_KEY = 'ssh-ed25519 255 SHA256:PesPlH50RqbZUVsJ36pht255bUudtwKPcjcTCyqeel4';
const SSH_KNOWN_KEY = 'ssh-ed25519 255 SHA256:r9KW3um9+d/8C1URZcwyDQTviw8hKY9+E0SawnlqQKE';
const SSH_KNOW_KEYS = [
    `${PCAP_HOST.replace(/:\d+$/, '')} ${SSH_KNOWN_KEY}`,
    '|1|V9t4eHtO+266YRGnqjskEx2a57o=|QvdHODP5Z/ZDnNZfHdcTBVMs1Bk= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKOV2iFvC8q5/lL7UpMu1mdp9wrUkiDHoCa3+fINm8geLdoegkxr4vjDJycs69hUfewisnYu/lxtD7T0O3iKC9I=',
    '|1|2EilM+qITJLZPysUUIz2FsPuwHQ=|bmay+fCwgQ1KhS1Zx8DPSoqiDH4= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKOV2iFvC8q5/lL7UpMu1mdp9wrUkiDHoCa3+fINm8geLdoegkxr4vjDJycs69hUfewisnYu/lxtD7T0O3iKC9I=',
    '|1|HNvT9qw+bEa2AyslNFtm1ImDHv0=|UuHC2sQofsmm6avv6V9VB92J4fo= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTUqewIb9mHH4U8RH8gqAMUuCHX7Oxr4IJFz/YO9mlO',
    '|1|nsUIhpml4biLln7RIiwOIiljrdg=|CqWiS+rNGfTcyz6EjCZ06SldUXY= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDF5TUPDocObD6CM+Q/t0+73cg7Jl+mXpOwjn+PgzTbIczNDP4ZTDe3E3c8uJsspFeE6sc8ps5/41dfn9AmaaLIXuCPSBV2E296f9tiXVXtuD4chadNsXOhxuXY3cW9Wv32vvkwDr4wE/LZZ+ABNa0stzRVWz51wQbTBUf0Btc3xrdecb85f6GAXQ7lJWWcrDiHL5tWh5oK8VejzU4oPP529GYZAlQREJahpMkVJ6zjJLKd7YbC//lVMnPxBu0Ydejt1CVWVhP5xIEyn1bRC8nXazaTNM4ZndUEW15uy5JXPIja/k5iG6OT/kMn6d088fpnjy3P9zeC4p3k02lN65DEum8sVUbGUFn9FTLN1Jj7e/aivXs2fdJoT9a8YcHHRyCkpk1AERX+advI3+5sbLmmYzBYNPt2WILmQQp4Rq/gNBu8kEFt4mlA3lMd5Fcov88b6nP1xfq8L9mJ59DUHlE+HlS5zCyuxch5TRTzqjKF1XlVEI2qVED3223dS5IvIxE=',
    '|1|UV6zb/i+DLBjbwNgzyY/h2K0mWI=|j2tYqmVxtohj5fihPhMr+4EopqY= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGeRfEXHAqtmvEg3OLm0RmvdMIkdimYuMwe/vEi1dlDz86K2PsmfhPA16eN7vF+T29gFW1zwwyRPti5kTCKmmTQ=',
];

// save files every 10 minutes
const SAVE_DATA_EVERY_MS = 600_000;
// save files if bigger than 50 Mb
const SAVE_DATA_IF_BIGGER = 50 * 1024 * 1024;

const SYNC_INTERVAL = 120_000; // 3_600_000;

type Device = {
    enabled: boolean;
    mac: string;
    ip: string;
    desc: string;
}

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
    devices: Device[];
    /** if recording is enabled */
    recordingEnabled: boolean;
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

    private sidCreated: number = 0;

    private startTimeout: ioBroker.Timeout | undefined;

    private syncProcess: ChildProcess | null = null;

    private context: Context = {
        terminate: false,
        controller: null,
        packets: [],
        totalBytes: 0,
        totalPackets: 0,
        buffer: Buffer.from([]),
        modifiedMagic: false,
        networkType: 1,
        lastSaved: 0,
    };

    private recordingRunning: boolean = false;

    private privateKeyPath: string = '';

    private knownHostFile: string = '';

    private workingDir: string = '';

    private rsyncPath: string = '';

    private syncRunning: boolean = false;

    private saveAfterSync: boolean = false;

    private syncTimer: NodeJS.Timeout | null = null;

    private monitorInterval: ioBroker.Interval | undefined;

    private static macCache: { [ip: string]: { mac: string; vendor?: string } } = {};

    public constructor(options: Partial<utils.AdapterOptions> = {}) {
        super({
            ...options,
            name: 'kisshome-research',
        });
        this.on('ready', () => this.onReady());
        this.on('unload', callback => this.onUnload(callback));
        this.on('message', this.onMessage.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
    }

    async onMessage(msg: ioBroker.Message): Promise<void> {
        const config: KISSHomeResearchConfig = this.config as unknown as KISSHomeResearchConfig;
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

                case 'getUsers': {
                    if (msg.callback) {
                        try {
                            if (msg.message?.ip || config.fritzbox) {
                                const users = await getFritzBoxUsers(msg.message?.ip || config.fritzbox);
                                this.sendTo(msg.from, msg.command, users, msg.callback);
                            } else {
                                this.sendTo(msg.from, msg.command, [], msg.callback);
                            }
                        } catch (e) {
                            this.sendTo(msg.from, msg.command, { error: e.message }, msg.callback);
                        }
                    }
                    break;
                }

                case 'getInterfaces': {
                    if (msg.callback) {
                        try {
                            if (msg.message?.ip || config.fritzbox &&
                                msg.message?.login || config.login &&
                                msg.message?.password || config.password
                            ) {
                                const ifaces = await getFritzBoxInterfaces(
                                    msg.message?.ip || config.fritzbox,
                                    msg.message?.login,
                                    msg.message?.password,
                                    msg.message?.login === config.login && msg.message.password === config.password ? this.sid : undefined,
                                );
                                this.sendTo(msg.from, msg.command, ifaces, msg.callback);
                            } else {
                                this.sendTo(msg.from, msg.command, [], msg.callback);
                            }
                        } catch (e) {
                            this.sendTo(msg.from, msg.command, { error: e.message }, msg.callback);
                        }
                    }
                    break;
                }

                case 'getMacForIps':
                    if (msg.callback) {
                        try {
                            const devices: Device[] = msg.message as Device[];
                            const result = await KISSHomeResearchAdapter.getMacForIps(devices.map(d => d.ip));
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
            await this.setState('info.recordingRunning', false, true);
        }

        const captured = await this.getStateAsync('info.capturedPackets');
        if (captured?.val) {
            await this.setState('info.capturedPackets', 0, true);
        }

        // try to get MAC addresses for all IPs
        const IPs = config.devices.filter(item => item.enabled && (item.ip || item.mac));
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
        if (!keysObj || !keysObj?.native?.publicKey || !keysObj.native?.privateKey) {
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

        // this.clearWorkingDir();

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

        // create a home known file
        const text = SSH_KNOW_KEYS.join('\n');
        if (!fs.existsSync(this.knownHostFile)) {
            this.log.debug(`Creating known_hosts file: ${this.knownHostFile}`);
            fs.writeFileSync(this.knownHostFile, text);
        } else if (fs.readFileSync(this.knownHostFile).toString('utf8') !== text) {
            this.log.warn(`Updating known_hosts file: ${this.knownHostFile}`);
            fs.writeFileSync(this.knownHostFile, text);
        }

        if (!config.email) {
            this.log.error('No email provided. Please provide an email address in the configuration');
            this.log.error('You must register this email first on https://kisshome-feldversuch.if-is.net/#register');
            return;
        }
        if (!config.recordingEnabled) {
            this.log.warn('Recording is not enabled. Do nothing');
            return;
        }

        try {
            // register on the cloud
            const response = await axios.post(`https://${PCAP_HOST}/api/v1/registerKey`, {
                publicKey: `ssh-ed25519 ${publicKey}`,
                email: config.email,
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
            if (process.platform === 'linux') {
                this.log.error(`Install rsync on your system: "sudo apt-get install rsync"`);
            }
            return;
        }

        this.log.debug(`[RSYNC] rsync path: ${this.rsyncPath}`);

        this.saveMetaFile(IPs);

        await this.setState('info.recordingRunning', false, true);
        await this.setState('info.recordingWrite', false, true);

        this.subscribeStates('info.recordingRunning');
        this.subscribeStates('info.recordingWrite');

        // start the monitoring
        this.startRecording(config)
            .catch(e => this.log.error(`[PCAP] Cannot start recording: ${e}`));

        this.log.debug(`[RSYNC] command: ${this.getRSyncCommand()}`);

        // Send the data every hour to the cloud
        this.syncTimer = setTimeout(() => {
            this.syncTimer = null;
            this.syncJob();
        }, SYNC_INTERVAL);
    }

    syncJob(): void {
        // Send the data every hour to the cloud
        if (this.syncTimer) {
            clearTimeout(this.syncTimer);
            this.syncTimer = null;
        }

        if (this.context.terminate) {
            return;
        }

        const started = Date.now();

        this.startSynchronization(() => {
            const duration = Date.now() - started;
            this.syncTimer = setTimeout(() => {
                this.syncTimer = null;
                this.syncJob();
            }, SYNC_INTERVAL - duration > 0 ? SYNC_INTERVAL - duration : 0);
        });
    }

    onStateChange(id: string, state: ioBroker.State | null | undefined): void {
        if (state) {
            if (id === `${this.namespace}.info.recordingRunning` && !state.ack) {
                if (state.val) {
                    if (!this.recordingRunning) {
                        const config: KISSHomeResearchConfig = this.config as unknown as KISSHomeResearchConfig;
                        this.startRecording(config)
                            .catch(e => this.log.error(`Cannot start recording: ${e}`));
                    }
                } else if (this.recordingRunning) {
                    this.context.terminate = true;
                    if (this.context.controller) {
                        this.context.controller.abort();
                        this.context.controller = null;
                    }
                }
            } else if (id === `${this.namespace}.info.recordingWrite` && !state.ack) {
                if (state.val) {
                    if (this.recordingRunning) {
                        this.setState('info.recordingWrite', false, true);
                        this.savePacketsToFile();
                    }
                }
            }
        }
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

            const fileName = `${this.workingDir}/${KISSHomeResearchAdapter.getTimestamp()}.pcap`;
            // get file descriptor of a file
            const fd = fs.openSync(fileName, 'w');
            let offset = 0;
            const magic = packetsToSave[0].readUInt32LE(0);
            const STANDARD_MAGIC = 0xa1b2c3d4;
            // https://wiki.wireshark.org/Development/LibpcapFileFormat
            const MODIFIED_MAGIC = 0xa1b2cd34;

            // do not save a header if it is already present
            if (magic !== STANDARD_MAGIC && magic !== MODIFIED_MAGIC) {
                // create PCAP header
                const byteArray = Buffer.alloc(6 * 4);
                // magic number
                byteArray.writeUInt32LE(this.context.modifiedMagic ? MODIFIED_MAGIC : STANDARD_MAGIC, 0);
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
                byteArray.writeUInt32LE(this.context.networkType, 20);
                fs.writeSync(fd, byteArray, 0, byteArray.length, 0);
                offset = byteArray.length;
            }

            // write header
            for (let i = 0; i < packetsToSave.length; i++) {
                const packet = packetsToSave[i];
                fs.writeSync(fd, packet, 0, packet.length, offset);
                offset += packet.length;
            }
            fs.closeSync(fd);
            this.log.debug(`Saved file ${fileName} with ${offset} bytes`);
        }
        this.context.lastSaved = Date.now();
    }

    async startRecording(config: KISSHomeResearchConfig) {
        // take sid from fritzbox
        if (!this.sid || !this.sidCreated || Date.now() - this.sidCreated >= 3_600_000) {
            try {
                this.sid = await getFritzBoxToken(config.fritzbox, config.login, config.password, (text: string) => this.log.warn(text));
                this.sidCreated = Date.now();
            } catch (e) {
                this.sid = '';
                this.sidCreated = 0;
                this.log.error(`[PCAP] Cannot get SID from FritzBox: ${e}`);
            }
        }

        if (this.sid) {
            this.log.debug(`[PCAP] Use SID: ${this.sid}`);

            const captured = await this.getStateAsync('info.capturedPackets');
            if (captured?.val) {
                await this.setState('info.capturedPackets', 0, true);
            }

            this.context.controller = new AbortController();

            this.context.packets = [];
            this.context.totalBytes = 0;
            this.context.totalPackets = 0;
            this.context.lastSaved = Date.now();

            // stop all recordings
            const response = await stopAllRecordingsOnFritzBox(config.fritzbox, this.sid);
            if (response) {
                this.log.info(`[PCAP] Stopped all recordings on FritzBox: ${response}`);
            }
            this.log.debug(`[PCAP] starting recording on ${config.fritzbox}/"${config.iface}"...`);
            this.log.debug(`[PCAP] ${getRecordURL(config.fritzbox, this.sid, config.iface, this.uniqueMacs)}`);

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
                        this.sidCreated = 0;
                    }

                    if (this.recordingRunning) {
                        this.log.info(`[PCAP] Recording stopped`);
                        this.recordingRunning = false;
                        this.setState('info.connection', false, true);
                        this.setState('info.recordingRunning', false, true);
                    }

                    if (this.context.packets?.length) {
                        this.setState('info.capturedPackets', this.context.totalPackets, true);
                    }

                    error && this.log.error(`[PCAP] Error while recording: ${error}`);
                    if (!this.context.terminate) {
                        this.restartRecording(config);
                    }
                },
                this.context,
                () => {
                    if (!this.recordingRunning) {
                        this.log.debug('[PCAP] Recording started!');
                        this.recordingRunning = true;
                        this.setState('info.connection', true, true);
                        this.setState('info.recordingRunning', true, true);

                        this.monitorInterval = this.monitorInterval || this.setInterval(() => {
                            this.log.debug(`[PCAP] Captured ${this.context.totalPackets} packets (${Math.round(this.context.totalBytes / (1024 * 1024) * 100) / 100} Mb)`);
                            // save if a file is bigger than 50 Mb
                            if (this.context.totalBytes > SAVE_DATA_IF_BIGGER ||
                                // save every 10 minutes
                                Date.now() - this.context.lastSaved >= SAVE_DATA_EVERY_MS
                            ) {
                                if (this.syncRunning) {
                                    this.saveAfterSync = true;
                                } else {
                                    this.savePacketsToFile();
                                }
                            }
                        }, 10000);
                    }

                    this.setState('info.capturedPackets', this.context.totalPackets, true);
                },
            );
        } else {
            this.log.warn('[PCAP] Cannot login into FritzBox. Maybe wrong credentials or fritzbox is not available');
            // try to get the token in 10 seconds again. E.g., if fritzbox is rebooting
            this.restartRecording(config);
        }
    }

    static getTimestamp(): string {
        const now = new Date();
        return `${now.getUTCFullYear()}-${(now.getUTCMonth() + 1).toString().padStart(2, '0')}-${now.getUTCDate().toString().padStart(2, '0')}_${now.getUTCHours().toString().padStart(2, '0')}-${now.getUTCMinutes().toString().padStart(2, '0')}-${now.getUTCSeconds().toString().padStart(2, '0')}`;
    }

    saveMetaFile(IPs: Device[]): void {
        const text = KISSHomeResearchAdapter.getDescriptionFile(IPs);
        let newFile = `${this.workingDir}/${KISSHomeResearchAdapter.getTimestamp()}_meta.json`;
        try {
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
                    fs.writeFileSync(newFile, text);
                }
            } else {
                this.log.info('Meta file created');
                // if not found => create new one
                fs.writeFileSync(newFile, text);
            }
        } catch (e) {
            this.log.warn(`Cannot save meta file "${newFile}": ${e}`);
        }
    }

    static getDescriptionFile(IPs: Device[]): string {
        const desc: Record<string, { ip: string; desc: string }>= {};
        IPs.sort((a, b) => a.ip.localeCompare(b.ip)).forEach(ip => {
            if (ip.mac) {
                desc[ip.mac] = { ip: ip.ip, desc: ip.desc };
            }
        });
        return JSON.stringify(desc, null, 2);
    }

    static async getMacForIps(ips: string[]): Promise<{ mac: string; vendor?: string, ip: string }[]> {
        const result: { mac: string; vendor?: string, ip: string }[] = [];
        let error: string = '';
        for (let ip of ips) {
            if (KISSHomeResearchAdapter.macCache[ip]) {
                result.push({ ...KISSHomeResearchAdapter.macCache[ip], ip });
                continue;
            }
            try {
                const mac = await getMacForIp(ip);
                if (mac) {
                    result.push(mac);
                    KISSHomeResearchAdapter.macCache[ip] = { mac: mac.mac, vendor: mac.vendor };
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
        this.context.terminate = true;

        if (this.recordingRunning) {
            this.recordingRunning = false;
            this.setState('info.connection', false, true);
            this.setState('info.recordingRunning', false, true);
        }
        if (this.syncTimer) {
            clearTimeout(this.syncTimer);
            this.syncTimer = null;
        }

        if (this.syncProcess?.pid) {
            try {
                await terminate(this.syncProcess.pid);
            } catch (err) {
                this.log.error(`Cannot terminate sync process: ${err}`);
            }
            this.syncProcess = null;
        }

        if (this.startTimeout) {
            clearTimeout(this.startTimeout);
            this.startTimeout = undefined;
        }

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
            this.log.error(`Cannot read working directory "${this.workingDir}": ${e}`);
        }
    }

    getRSyncCommand(): string {
        const cmd: string[] = [
            this.rsyncPath,
            '-avr',
            '-e',
            `"ssh -o UserKnownHostsFile=${this.knownHostFile} -i ${this.privateKeyPath}"`,
            this.workingDir,
            `pcaprecv@${PCAP_HOST.replace(/:\d+$/, '')}:/dummyPath/`,
        ];

        return cmd.join(' ');
    }

    startSynchronization(cb?: () => void): void {
        // calculate the total number of bytes
        let totalBytes = 0;
        this.log.debug(`[RSYNC] Start synchronization...`);

        // calculate the total number of bytes in pcap files
        try {
            const files = fs.readdirSync(this.workingDir);
            for (const file of files) {
                if (file.endsWith('.pcap')) {
                    totalBytes += fs.statSync(`${this.workingDir}/${file}`).size;
                }
            }
        } catch (e) {
            this.log.error(`[RSYNC] Cannot read working directory for sync "${this.workingDir}": ${e}`);
            if (cb) {
                cb();
            }
            return;
        }

        if (!totalBytes) {
            this.log.debug(`[RSYNC] No files to sync`);
            if (cb) {
                cb();
            }
            return;
        }

        if (this.syncRunning) {
            this.log.warn(`[RSYNC] Synchronization still running...`);
            if (cb) {
                cb();
            }
            return;
        }

        this.syncRunning = true;
        this.setState('info.syncRunning', true, true);

        this.log.debug(`[RSYNC] Syncing files to the cloud (${Math.round(totalBytes / (1024 * 1024) * 100) / 100} Mb)`);

        const cmd = this.getRSyncCommand();

        let error = '';

        this.log.debug(`[RSYNC] cmd: "${cmd}"`);

        this.syncProcess = exec(cmd, (_error, stdout, stderr) => {
            (stderr || _error) && this.log.warn(`[RSYNC] Error by synchronization: ${stderr}, ${_error}`);
            error = _error ? _error.message : '';
        });

        this.syncProcess.on('error', (_error) => error = _error.message);

        this.syncProcess.on('exit', (code) => {
            this.syncProcess = null;

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
                this.log.warn(`[RSYNC] Cannot sync files. rsync returned ${code}, error: ${error}`);
            } else {
                this.log.debug(`[RSYNC] Syncing files done with code ${code}`);
            }

            if (cb) {
                cb();
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

"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.KISSHomeResearchAdapter = void 0;
const utils = __importStar(require("@iobroker/adapter-core"));
const node_fs_1 = __importDefault(require("node:fs"));
const axios_1 = __importDefault(require("axios"));
const node_path_1 = __importDefault(require("node:path"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const utils_1 = require("./lib/utils");
const recording_1 = require("./lib/recording");
const fritzbox_1 = require("./lib/fritzbox");
const PCAP_HOST = 'kisshome-experiments.if-is.net';
// save files every 60 minutes
const SAVE_DATA_EVERY_MS = 3600000;
// save files if bigger than 50 Mb
const SAVE_DATA_IF_BIGGER = 50 * 1024 * 1024;
const SYNC_INTERVAL = 3600000; // 3_600_000;
function size2text(size) {
    if (size < 1024) {
        return `${size} B`;
    }
    if (size < 1024 * 1024) {
        return `${Math.round((size * 10) / 1024) / 10} kB`;
    }
    return `${Math.round((size * 10) / (1024 * 1024) / 10)} MB`;
}
class KISSHomeResearchAdapter extends utils.Adapter {
    constructor(options = {}) {
        super({
            ...options,
            name: 'kisshome-research',
        });
        this.tempDir = '';
        this.uniqueMacs = [];
        this.__dirname = __dirname;
        this.sid = '';
        this.sidCreated = 0;
        this.context = {
            terminate: false,
            controller: null,
            packets: [],
            totalBytes: 0,
            totalPackets: 0,
            buffer: Buffer.from([]),
            modifiedMagic: false,
            libpCapFormat: false,
            networkType: 1,
            started: 0,
            lastSaved: 0,
        };
        this.recordingRunning = false;
        this.workingDir = '';
        this.lastDebug = 0;
        this.syncRunning = false;
        this.syncTimer = null;
        this.publicKey = '';
        this.uuid = '';
        this.recordingEnabled = false;
        this.on('ready', () => this.onReady());
        this.on('unload', callback => this.onUnload(callback));
        this.on('message', this.onMessage.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
    }
    async onMessage(msg) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q;
        const config = this.config;
        if (typeof msg === 'object' && msg.message) {
            switch (msg.command) {
                case 'getDefaultGateway':
                    if (msg.callback) {
                        if (msg.message.value !== '0.0.0.0') {
                            this.sendTo(msg.from, msg.command, msg.message.value, msg.callback);
                        }
                        else {
                            try {
                                const ip = await (0, utils_1.getDefaultGateway)();
                                this.sendTo(msg.from, msg.command, ip, msg.callback);
                            }
                            catch (e) {
                                this.sendTo(msg.from, msg.command, { error: e.message }, msg.callback);
                            }
                        }
                    }
                    break;
                case 'getUsers': {
                    if (msg.callback) {
                        try {
                            if (((_a = msg.message) === null || _a === void 0 ? void 0 : _a.ip) || config.fritzbox) {
                                const users = await (0, fritzbox_1.getFritzBoxUsers)(((_b = msg.message) === null || _b === void 0 ? void 0 : _b.ip) || config.fritzbox);
                                this.sendTo(msg.from, msg.command, users, msg.callback);
                            }
                            else {
                                this.sendTo(msg.from, msg.command, [], msg.callback);
                            }
                        }
                        catch (e) {
                            this.sendTo(msg.from, msg.command, { error: e.message }, msg.callback);
                        }
                    }
                    break;
                }
                case 'getFilter': {
                    if (msg.callback) {
                        try {
                            if (((_c = msg.message) === null || _c === void 0 ? void 0 : _c.ip) ||
                                (config.fritzbox && ((_d = msg.message) === null || _d === void 0 ? void 0 : _d.login)) ||
                                (config.login && ((_e = msg.message) === null || _e === void 0 ? void 0 : _e.password)) ||
                                config.password) {
                                const filter = await (0, fritzbox_1.getFritzBoxFilter)(((_f = msg.message) === null || _f === void 0 ? void 0 : _f.ip) || config.fritzbox, ((_g = msg.message) === null || _g === void 0 ? void 0 : _g.login) || config.login, ((_h = msg.message) === null || _h === void 0 ? void 0 : _h.password) || config.password);
                                this.sendTo(msg.from, msg.command, {
                                    text: filter
                                        ? 'Fritz!Box unterstuetzt Filter-Funktion'
                                        : 'Fritz!Box unterstuetzt Filter-Funktion nicht',
                                    style: {
                                        color: filter ? 'green' : 'red',
                                    },
                                }, msg.callback);
                            }
                            else {
                                this.sendTo(msg.from, msg.command, false, msg.callback);
                            }
                        }
                        catch (e) {
                            this.sendTo(msg.from, msg.command, { error: e.message }, msg.callback);
                        }
                    }
                    break;
                }
                case 'getInterfaces': {
                    if (msg.callback) {
                        try {
                            if (((_j = msg.message) === null || _j === void 0 ? void 0 : _j.ip) ||
                                (config.fritzbox && ((_k = msg.message) === null || _k === void 0 ? void 0 : _k.login)) ||
                                (config.login && ((_l = msg.message) === null || _l === void 0 ? void 0 : _l.password)) ||
                                config.password) {
                                const ifaces = await (0, fritzbox_1.getFritzBoxInterfaces)(((_m = msg.message) === null || _m === void 0 ? void 0 : _m.ip) || config.fritzbox, (_o = msg.message) === null || _o === void 0 ? void 0 : _o.login, (_p = msg.message) === null || _p === void 0 ? void 0 : _p.password, ((_q = msg.message) === null || _q === void 0 ? void 0 : _q.login) === config.login && msg.message.password === config.password
                                    ? this.sid
                                    : undefined);
                                const lan1 = ifaces === null || ifaces === void 0 ? void 0 : ifaces.find(i => i.label === '1-lan');
                                if (lan1) {
                                    lan1.label += ' (default)';
                                }
                                const index = ifaces === null || ifaces === void 0 ? void 0 : ifaces.findIndex(it => it === lan1);
                                // place lan1 on the first position
                                if (ifaces && index && index !== -1) {
                                    ifaces.splice(0, 0, ifaces.splice(index, 1)[0]);
                                }
                                this.sendTo(msg.from, msg.command, ifaces, msg.callback);
                            }
                            else {
                                this.sendTo(msg.from, msg.command, [], msg.callback);
                            }
                        }
                        catch (e) {
                            this.sendTo(msg.from, msg.command, { error: e.message }, msg.callback);
                        }
                    }
                    break;
                }
                case 'getMacForIps':
                    if (msg.callback) {
                        try {
                            const devices = msg.message;
                            const result = await KISSHomeResearchAdapter.getMacForIps(devices);
                            this.sendTo(msg.from, msg.command, { result }, msg.callback);
                        }
                        catch (e) {
                            this.sendTo(msg.from, msg.command, { error: e.message }, msg.callback);
                        }
                    }
                    break;
            }
        }
    }
    async analyseError(response) {
        if (response.status === 404) {
            this.log.error(`Cannot register on the kisshome-cloud: Unknown email address`);
            this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: Unbekannte E-Mail-Adresse`);
        }
        else if (response.status === 403) {
            this.log.error(`Cannot register on the kisshome-cloud: public key changed. Please contact us via kisshome@internet-sicherheit.de`);
            this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: Der öffentliche Schlüssel hat sich geändert. Bitte kontaktieren Sie uns unter kisshome@internet-sicherheit.de`);
            await this.registerNotification('kisshome-research', 'publicKey', 'Public key changed');
        }
        else if (response.status === 401) {
            this.log.error(`Cannot register on the cloud: invalid password`);
            this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: Ungültiges Passwort`);
        }
        else if (response.status === 422) {
            this.log.error(`Cannot register on the cloud: missing email, public key or uuid`);
            this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: E-Mail, öffentlicher Schlüssel oder UUID fehlen`);
        }
        else {
            this.log.error(`Cannot register on the kisshome-cloud: ${response.data || response.statusText || response.status}`);
            this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: ${response.data || response.statusText || response.status}`);
        }
    }
    async onReady() {
        var _a, _b, _c, _d, _e;
        const config = this.config;
        // read UUID
        const uuidObj = await this.getForeignObjectAsync('system.meta.uuid');
        if ((_a = uuidObj === null || uuidObj === void 0 ? void 0 : uuidObj.native) === null || _a === void 0 ? void 0 : _a.uuid) {
            this.uuid = uuidObj.native.uuid;
        }
        else {
            this.log.error('Cannot read UUID');
            this.log.error('Kann UUID nicht auslesen');
            return;
        }
        // first, try to detect the default gateway
        // if (config.fritzbox === '0.0.0.0') {
        //     try {
        //         const ip = await getDefaultGateway();
        //         if (ip && ip !== '0.0.0.0') {
        //             this.log.info(`Found default gateway: ${ip}`);
        //             config.fritzbox = ip;
        //             const obj = await this.getForeignObjectAsync(`system.adapter.${this.namespace}`);
        //             if (obj) {
        //                 obj.native.fritzbox = ip;
        //                 await this.setForeignObjectAsync(obj._id, obj);
        //                 // wait for restart
        //                 return;
        //             }
        //         }
        //     } catch (e) {
        //         this.log.warn(`Cannot get default gateway: ${e}`);
        //     }
        // }
        // remove running flag
        const runningState = await this.getStateAsync('info.connection');
        if (runningState === null || runningState === void 0 ? void 0 : runningState.val) {
            await this.setState('info.connection', false, true);
            await this.setState('info.recording.running', false, true);
        }
        const captured = await this.getStateAsync('info.recording.captured');
        if (captured === null || captured === void 0 ? void 0 : captured.val) {
            await this.setState('info.recording.captured', 0, true);
        }
        // try to get MAC addresses for all IPs
        const IPs = config.devices.filter(item => item.enabled && (item.ip || item.mac));
        const tasks = IPs.filter(ip => !ip.mac);
        if (tasks.length) {
            try {
                const macs = await KISSHomeResearchAdapter.getMacForIps(tasks);
                for (let i = 0; i < tasks.length; i++) {
                    const mac = macs[i];
                    if (mac === null || mac === void 0 ? void 0 : mac.mac) {
                        const item = IPs.find(t => t.ip === mac.ip);
                        if (item) {
                            item.mac = mac.mac;
                        }
                    }
                }
            }
            catch (e) {
                this.log.error(`Cannot get MAC addresses: ${e}`);
                this.log.error(`MAC-Adressen können nicht ermittelt werden: ${e}`);
            }
        }
        // take only unique MAC addresses
        this.uniqueMacs = [];
        IPs.forEach(item => !this.uniqueMacs.includes(item.mac) && this.uniqueMacs.push(item.mac));
        // detect temp directory
        this.tempDir = config.tempDir || '/run/shm';
        if (node_fs_1.default.existsSync(this.tempDir)) {
            this.log.info(`Using ${this.tempDir} as temporary directory`);
            this.log.info(`${this.tempDir} wird als temporäres Verzeichnis verwendet`);
        }
        else if (node_fs_1.default.existsSync('/run/shm')) {
            this.tempDir = '/run/shm';
            this.log.info(`Using ${this.tempDir} as temporary directory`);
            this.log.info(`${this.tempDir} wird als temporäres Verzeichnis verwendet`);
        }
        else if (node_fs_1.default.existsSync('/tmp')) {
            this.tempDir = '/tmp';
            this.log.info(`Using ${this.tempDir} as temporary directory`);
            this.log.info(`${this.tempDir} wird als temporäres Verzeichnis verwendet`);
        }
        else {
            this.log.warn(`Cannot find any temporary directory. Please specify manually in the configuration. For best performance it should be a RAM disk`);
            this.log.warn(`Es kann kein temporäres Verzeichnis gefunden werden. Bitte geben Sie es manuell in der Konfiguration an. Für beste Leistung sollte es eine RAM-Disk sein.`);
            return;
        }
        this.tempDir = this.tempDir.replace(/\\/g, '/');
        if (this.tempDir.endsWith('/')) {
            this.tempDir = this.tempDir.substring(0, this.tempDir.length - 1);
        }
        let privateKey;
        // retrieve public and private keys
        let keysObj;
        try {
            keysObj = (await this.getObjectAsync('info.sync.keys'));
            if (!keysObj) {
                // try to migrate configuration
                keysObj = (await this.getObjectAsync('info.keys'));
                if (keysObj) {
                    await this.setObjectAsync('info.sync.keys', keysObj);
                    await this.delObjectAsync('info.keys');
                }
            }
        }
        catch {
            // ignore
            keysObj = null;
        }
        if (!keysObj || !((_b = keysObj === null || keysObj === void 0 ? void 0 : keysObj.native) === null || _b === void 0 ? void 0 : _b.publicKey) || !((_c = keysObj.native) === null || _c === void 0 ? void 0 : _c.privateKey)) {
            this.log.info('Generating keys for the first time.');
            this.log.info('Schlüssel werden erstmalig generiert.');
            const result = (0, utils_1.generateKeys)();
            privateKey = result.privateKey;
            this.publicKey = result.publicKey;
            keysObj = {
                _id: 'info.sync.keys',
                type: 'config',
                common: {
                    name: {
                        en: 'Public and private keys',
                        de: 'öffentliche und private Schlüssel',
                        ru: 'Публичные и частные ключи',
                        pt: 'Chaves públicas e privadas',
                        nl: 'Openbare en privésleutels',
                        fr: 'Clés publiques et privées',
                        it: 'Chiavi pubbliche e private',
                        es: 'Claves públicas y privadas',
                        pl: 'Klucze publiczne i prywatne',
                        uk: 'Публічні та приватні ключі',
                        'zh-cn': '公钥和私钥',
                    },
                },
                native: {
                    publicKey: this.publicKey,
                    privateKey,
                },
            };
            await this.setObjectAsync(keysObj._id, keysObj);
        }
        else {
            privateKey = keysObj.native.privateKey;
            this.publicKey = keysObj.native.publicKey;
        }
        if (!this.publicKey || !privateKey) {
            this.log.error('Cannot generate keys.');
            this.log.error('Schlüssel können nicht generiert werden.');
            return;
        }
        this.workingDir = `${this.tempDir}/hourly_pcaps`;
        // create hourly directory
        try {
            if (!node_fs_1.default.existsSync(this.workingDir)) {
                node_fs_1.default.mkdirSync(this.workingDir);
            }
        }
        catch (e) {
            this.log.error(`Cannot create working directory "${this.workingDir}": ${e}`);
            this.log.error(`Arbeitsverzeichnis "${this.workingDir}" kann nicht erstellt werden: ${e}`);
            return;
        }
        // this.clearWorkingDir();
        if (!config.email) {
            this.log.error('No email provided. Please provide an email address in the configuration.');
            this.log.error('Keine E-Mail angegeben. Bitte geben Sie eine E-Mail-Adresse in der Konfiguration an.');
            this.log.error('You must register this email first on https://kisshome-feldversuch.if-is.net/#register.');
            this.log.error('Sie müssen diese E-Mail zuerst unter https://kisshome-feldversuch.if-is.net/#register registrieren.');
            return;
        }
        try {
            // register on the cloud
            const response = await axios_1.default.post(`https://${PCAP_HOST}/api/v1/registerKey`, {
                publicKey: this.publicKey,
                email: config.email,
                uuid: this.uuid,
            });
            if (response.status === 200) {
                if (((_d = response.data) === null || _d === void 0 ? void 0 : _d.command) === 'terminate') {
                    this.log.warn('Server requested to terminate the adapter');
                    this.log.warn('Server hat die Terminierung des Adapters angefordert');
                    const obj = await this.getForeignObjectAsync(`system.adapter.${this.namespace}`);
                    if ((_e = obj === null || obj === void 0 ? void 0 : obj.common) === null || _e === void 0 ? void 0 : _e.enabled) {
                        obj.common.enabled = false;
                        await this.setForeignObjectAsync(obj._id, obj);
                    }
                }
                else {
                    this.log.info('Successfully registered on the cloud');
                    this.log.info('Erfolgreich in der Cloud registriert');
                }
            }
            else {
                await this.analyseError(response);
                return;
            }
        }
        catch (e) {
            if (e.response) {
                await this.analyseError(e.response);
            }
            else {
                this.log.error(`Cannot register on the kisshome-cloud: ${e}`);
                this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: ${e}`);
            }
            return;
        }
        this.saveMetaFile(IPs);
        await this.setState('info.recording.running', false, true);
        await this.setState('info.recording.triggerWrite', false, true);
        this.subscribeStates('info.recording.enabled');
        this.subscribeStates('info.recording.triggerWrite');
        this.recordingEnabled = ((await this.getStateAsync('info.recording.enabled')) || {}).val || false;
        if (this.recordingEnabled) {
            // start the monitoring
            this.startRecording(config).catch(e => {
                this.log.error(`[PCAP] Cannot start recording: ${e}`);
                this.log.error(`[PCAP] Aufzeichnen kann nicht gestartet werden: ${e}`);
            });
            // Send the data every hour to the cloud
            this.syncJob();
        }
        else {
            this.log.warn('Recording is not enabled. Do nothing.');
            this.log.warn('Aufzeichnen ist nicht aktiviert. Nichts passiert.');
        }
    }
    syncJob() {
        // Send the data every hour to the cloud
        if (this.syncTimer) {
            clearTimeout(this.syncTimer);
            this.syncTimer = null;
        }
        if (this.context.terminate) {
            return;
        }
        const started = Date.now();
        void this.startSynchronization()
            .catch(e => {
            this.log.error(`[RSYNC] Cannot synchronize: ${e}`);
            this.log.error(`[RSYNC] Kann nicht synchronisieren: ${e}`);
        })
            .then(() => {
            const duration = Date.now() - started;
            this.syncTimer = setTimeout(() => {
                this.syncTimer = null;
                this.syncJob();
            }, SYNC_INTERVAL - duration > 0 ? SYNC_INTERVAL - duration : 0);
        });
    }
    onStateChange(id, state) {
        if (state) {
            if (id === `${this.namespace}.info.recording.enabled` && !state.ack) {
                if (state.val) {
                    // If recording is not running
                    if (!this.recordingEnabled) {
                        this.recordingEnabled = true;
                        this.context.terminate = false;
                        const config = this.config;
                        this.startRecording(config).catch(e => {
                            this.log.error(`Cannot start recording: ${e}`);
                            this.log.error(`Aufzeichnen kann nicht gestartet werden: ${e}`);
                        });
                    }
                }
                else if (this.recordingEnabled) {
                    this.recordingEnabled = false;
                    this.context.terminate = true;
                    if (this.context.controller) {
                        this.context.controller.abort();
                        this.context.controller = null;
                    }
                }
            }
            else if (id === `${this.namespace}.info.recording.triggerWrite` && !state.ack) {
                if (state.val) {
                    if (this.recordingRunning) {
                        void this.setState('info.recording.triggerWrite', false, true).catch(e => this.log.error(`Cannot set triggerWrite: ${e}`));
                        this.savePacketsToFile();
                        setTimeout(() => {
                            this.startSynchronization().catch(e => {
                                this.log.error(`[RSYNC] Cannot synchronize: ${e}`);
                                this.log.error(`[RSYNC] Kann nicht synchronisieren: ${e}`);
                            });
                        }, 2000);
                    }
                }
            }
        }
    }
    restartRecording(config) {
        this.startTimeout && clearTimeout(this.startTimeout);
        this.startTimeout = this.setTimeout(() => {
            this.startTimeout = undefined;
            this.startRecording(config).catch(e => {
                this.log.error(`Cannot start recording: ${e}`);
                this.log.error(`Aufzeichnen kann nicht gestartet werden: ${e}`);
            });
        }, 10000);
    }
    savePacketsToFile() {
        if (this.context.packets.length) {
            const packetsToSave = this.context.packets;
            this.context.packets = [];
            this.context.totalBytes = 0;
            const timeStamp = KISSHomeResearchAdapter.getTimestamp();
            const fileName = `${this.workingDir}/${timeStamp}.pcap`;
            // get file descriptor of a file
            const fd = node_fs_1.default.openSync(fileName, 'w');
            let offset = 0;
            const magic = packetsToSave[0].readUInt32LE(0);
            const STANDARD_MAGIC = 0xa1b2c3d4;
            // https://wiki.wireshark.org/Development/LibpcapFileFormat
            const MODIFIED_MAGIC = 0xa1b2cd34;
            // do not save a header if it is already present
            // write header
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
                byteArray.writeUInt16LE(recording_1.MAX_PACKET_LENGTH, 16);
                // network type
                byteArray.writeUInt32LE(this.context.networkType, 20);
                node_fs_1.default.writeSync(fd, byteArray, 0, byteArray.length, 0);
                offset = byteArray.length;
            }
            for (let i = 0; i < packetsToSave.length; i++) {
                const packet = packetsToSave[i];
                node_fs_1.default.writeSync(fd, packet, 0, packet.length, offset);
                offset += packet.length;
            }
            node_fs_1.default.closeSync(fd);
            this.log.debug(`Saved file ${fileName} with ${size2text(offset)}`);
            this.log.debug(`Datei ${fileName} mit ${size2text(offset)} gespeichert`);
        }
        this.context.lastSaved = Date.now();
    }
    calculateMd5(content) {
        const hash = node_crypto_1.default.createHash('md5');
        hash.update(content);
        return hash.digest('hex');
    }
    async startRecording(config) {
        // take sid from fritzbox
        if (!this.sid || !this.sidCreated || Date.now() - this.sidCreated >= 3600000) {
            try {
                this.sid =
                    (await (0, fritzbox_1.getFritzBoxToken)(config.fritzbox, config.login, config.password, (text) => this.log.warn(text))) || '';
                this.sidCreated = Date.now();
            }
            catch (e) {
                this.sid = '';
                this.sidCreated = 0;
                this.log.error(`[PCAP] Cannot get SID from Fritz!Box: ${e}`);
                this.log.error(`[PCAP] SID kann nicht von Fritz!Box abgerufen werden : ${e}`);
            }
        }
        if (this.sid) {
            this.log.debug(`[PCAP] Use SID: ${this.sid}`);
            this.log.debug(`[PCAP] Nutze SID: ${this.sid}`);
            const captured = await this.getStateAsync('info.recording.captured');
            if (captured === null || captured === void 0 ? void 0 : captured.val) {
                await this.setState('info.recording.captured', 0, true);
            }
            this.context.controller = new AbortController();
            this.context.packets = [];
            this.context.totalBytes = 0;
            this.context.totalPackets = 0;
            this.context.lastSaved = Date.now();
            // stop all recordings
            const response = await (0, recording_1.stopAllRecordingsOnFritzBox)(config.fritzbox, this.sid);
            if (response) {
                this.log.info(`[PCAP] Stopped all recordings on Fritz!Box: ${response}`);
                this.log.info(`[PCAP] Alle Aufnahmen auf der Fritz!Box wurden beendet: ${response}`);
            }
            this.log.debug(`[PCAP] Starting recording on ${config.fritzbox}/"${config.iface}"...`);
            this.log.debug(`[PCAP] Starte das Mitschneiden von ${config.fritzbox}/"${config.iface}"...`);
            this.log.debug(`[PCAP] ${(0, recording_1.getRecordURL)(config.fritzbox, this.sid, config.iface, this.uniqueMacs)}`);
            (0, recording_1.startRecordingOnFritzBox)(config.fritzbox, this.sid, config.iface, this.uniqueMacs, async (error) => {
                var _a;
                this.monitorInterval && this.clearInterval(this.monitorInterval);
                this.monitorInterval = undefined;
                this.savePacketsToFile();
                this.context.totalBytes = 0;
                this.context.totalPackets = 0;
                if ((error === null || error === void 0 ? void 0 : error.message) === 'Unauthorized') {
                    this.sid = '';
                    this.sidCreated = 0;
                }
                if (this.recordingRunning) {
                    this.log.info(`[PCAP] Recording stopped.`);
                    this.log.info(`[PCAP] Mitschneiden beendet.`);
                    this.recordingRunning = false;
                    await this.setState('info.connection', false, true);
                    await this.setState('info.recording.running', false, true);
                }
                if ((_a = this.context.packets) === null || _a === void 0 ? void 0 : _a.length) {
                    await this.setState('info.recording.captured', this.context.totalPackets, true);
                }
                if (error) {
                    if (!this.context.terminate || !error.toString().includes('aborted')) {
                        this.log.error(`[PCAP] Error while recording: ${error.toString()}`);
                        this.log.error(`[PCAP] Fehler wehrend dem Mitschneiden: ${error.toString()}`);
                    }
                }
                if (!this.context.terminate) {
                    this.restartRecording(config);
                }
            }, this.context, async () => {
                if (!this.recordingRunning) {
                    this.log.debug('[PCAP] Recording started!');
                    this.log.debug('[PCAP] Aufzeichnen hat gestartet!');
                    this.recordingRunning = true;
                    await this.setState('info.connection', true, true);
                    await this.setState('info.recording.running', true, true);
                    this.monitorInterval =
                        this.monitorInterval ||
                            this.setInterval(() => {
                                if (Date.now() - this.lastDebug > 60000) {
                                    this.log.debug(`[PCAP] Captured ${this.context.totalPackets} packets (${size2text(this.context.totalBytes)})`);
                                    this.log.debug(`[PCAP] ${this.context.totalPackets} Pakete (${size2text(this.context.totalBytes)}) aufgezeichnet`);
                                    this.lastDebug = Date.now();
                                }
                                // save if a file is bigger than 50 Mb
                                if (this.context.totalBytes > SAVE_DATA_IF_BIGGER ||
                                    // save every 20 minutes
                                    Date.now() - this.context.lastSaved >= SAVE_DATA_EVERY_MS) {
                                    this.savePacketsToFile();
                                    if (!this.context.terminate) {
                                        this.startSynchronization().catch(e => {
                                            this.log.error(`[RSYNC] Cannot synchronize: ${e}`);
                                            this.log.error(`[RSYNC] Kann nicht synchronisieren: ${e}`);
                                        });
                                    }
                                }
                            }, 10000);
                }
                await this.setState('info.recording.captured', this.context.totalPackets, true);
            }, (text, level = 'info') => {
                this.log[level](`[PCAP] ${text}`);
            });
        }
        else {
            this.log.warn('[PCAP] Cannot login into Fritz!Box. Could be wrong credentials or Fritz!Box is not available');
            this.log.warn('[PCAP] Anmelden auf Fritz!Box nicht möglich. Vermutlich falsche Anmeldedaten oder die Fritz!Box ist nicht verfügbar.');
            // try to get the token in 10 seconds again. E.g., if fritzbox is rebooting
            this.restartRecording(config);
        }
    }
    static getTimestamp() {
        const now = new Date();
        return `${now.getUTCFullYear()}-${(now.getUTCMonth() + 1).toString().padStart(2, '0')}-${now.getUTCDate().toString().padStart(2, '0')}_${now.getUTCHours().toString().padStart(2, '0')}-${now.getUTCMinutes().toString().padStart(2, '0')}-${now.getUTCSeconds().toString().padStart(2, '0')}`;
    }
    saveMetaFile(IPs) {
        const text = KISSHomeResearchAdapter.getDescriptionFile(IPs);
        const newFile = `${this.workingDir}/${KISSHomeResearchAdapter.getTimestamp()}_meta.json`;
        try {
            // find the latest file
            const files = node_fs_1.default.readdirSync(this.workingDir);
            files.sort((a, b) => b.localeCompare(a));
            let latestFile = '';
            // find the latest file and delete all other _meta.json files
            for (const file of files) {
                if (!latestFile && file.endsWith('_meta.json')) {
                    latestFile = file;
                }
                else if (file.endsWith('_meta.json')) {
                    node_fs_1.default.unlinkSync(`${this.workingDir}/${file}`);
                }
            }
            // if existing meta file found
            if (latestFile) {
                // compare the content
                const oldFile = node_fs_1.default.readFileSync(`${this.workingDir}/${latestFile}`, 'utf8');
                if (oldFile !== text) {
                    this.log.debug('Meta file updated');
                    this.log.debug('Meta-Datei aktualisiert');
                    node_fs_1.default.unlinkSync(`${this.workingDir}/${latestFile}`);
                    node_fs_1.default.writeFileSync(newFile, text);
                }
            }
            else {
                this.log.info('Meta file created');
                this.log.info('Meta-Datei wurde angelegt.');
                // if not found => create new one
                node_fs_1.default.writeFileSync(newFile, text);
            }
        }
        catch (e) {
            this.log.warn(`Cannot save meta file "${newFile}": ${e}`);
            this.log.warn(`Speicher von Meta-Datei "${newFile}" nicht möglich: ${e}`);
        }
    }
    static getDescriptionFile(IPs) {
        const desc = {};
        IPs.sort((a, b) => a.ip.localeCompare(b.ip)).forEach(ip => {
            if (ip.mac) {
                desc[ip.mac] = { ip: ip.ip, desc: ip.desc };
            }
        });
        return JSON.stringify(desc, null, 2);
    }
    static async getMacForIps(devices) {
        const result = [];
        let error = '';
        for (const dev of devices) {
            if (dev.ip && KISSHomeResearchAdapter.macCache[dev.ip]) {
                result.push({ ...KISSHomeResearchAdapter.macCache[dev.ip], ip: dev.ip, found: true });
                continue;
            }
            if (!dev.mac && dev.ip && (0, utils_1.validateIpAddress)(dev.ip)) {
                try {
                    const mac = await (0, utils_1.getMacForIp)(dev.ip);
                    if (mac) {
                        result.push({ ...mac, found: true });
                        KISSHomeResearchAdapter.macCache[dev.ip] = { mac: mac.mac, vendor: mac.vendor };
                    }
                }
                catch (e) {
                    error = e.message;
                }
            }
            else {
                const item = {
                    mac: dev.mac,
                    ip: dev.ip,
                    vendor: dev.mac ? (0, utils_1.getVendorForMac)(dev.mac) : '',
                    found: false,
                };
                result.push(item);
            }
        }
        if (!result.length && devices.length) {
            throw new Error(error || 'no results');
        }
        return result;
    }
    async onUnload(callback) {
        this.context.terminate = true;
        if (this.recordingRunning) {
            this.recordingRunning = false;
            await this.setState('info.connection', false, true);
            await this.setState('info.recording.running', false, true);
        }
        if (this.syncTimer) {
            clearTimeout(this.syncTimer);
            this.syncTimer = null;
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
        }
        catch {
            callback();
        }
    }
    clearWorkingDir() {
        try {
            const files = node_fs_1.default.readdirSync(this.workingDir);
            for (const file of files) {
                if (file.endsWith('.pcap')) {
                    try {
                        node_fs_1.default.unlinkSync(`${this.workingDir}/${file}`);
                    }
                    catch (e) {
                        this.log.error(`Cannot delete file ${this.workingDir}/${file}: ${e}`);
                        this.log.error(`Die Datei ${this.workingDir}/${file} kann nicht gelöscht werden: ${e}`);
                    }
                }
                else if (!file.endsWith('.json')) {
                    // delete unknown files
                    try {
                        node_fs_1.default.unlinkSync(`${this.workingDir}/${file}`);
                    }
                    catch (e) {
                        this.log.error(`Cannot delete file ${this.workingDir}/${file}: ${e}`);
                        this.log.error(`Die Datei ${this.workingDir}/${file} kann nicht gelöscht werden: ${e}`);
                    }
                }
            }
        }
        catch (e) {
            this.log.error(`Cannot read working directory "${this.workingDir}": ${e}`);
            this.log.error(`Arbeitsverzeichnis „${this.workingDir}“ kann nicht gelesen werden: ${e}`);
        }
    }
    async sendOneFileToCloud(fileName) {
        var _a, _b;
        const config = this.config;
        try {
            const data = node_fs_1.default.readFileSync(fileName);
            const name = node_path_1.default.basename(fileName);
            const len = data.length;
            const md5 = this.calculateMd5(data);
            // check if the file was sent successfully
            try {
                const responseCheck = await axios_1.default.get(`https://${PCAP_HOST}/api/v1/upload/${encodeURIComponent(config.email)}/${encodeURIComponent(name)}?key=${encodeURIComponent(this.publicKey)}&uuid=${encodeURIComponent(this.uuid)}`);
                if (((_a = responseCheck.data) === null || _a === void 0 ? void 0 : _a.command) === 'terminate') {
                    const obj = await this.getForeignObjectAsync(`system.adapter.${this.namespace}`);
                    if ((_b = obj === null || obj === void 0 ? void 0 : obj.common) === null || _b === void 0 ? void 0 : _b.enabled) {
                        obj.common.enabled = false;
                        await this.setForeignObjectAsync(obj._id, obj);
                    }
                    return;
                }
                if (responseCheck.status === 200 && responseCheck.data === md5) {
                    // file already uploaded, do not upload it again
                    if (name.endsWith('.pcap')) {
                        node_fs_1.default.unlinkSync(fileName);
                    }
                    return;
                }
            }
            catch {
                // ignore
            }
            const responsePost = await (0, axios_1.default)({
                method: 'post',
                url: `https://${PCAP_HOST}/api/v1/upload/${encodeURIComponent(config.email)}/${encodeURIComponent(name)}?key=${encodeURIComponent(this.publicKey)}&uuid=${encodeURIComponent(this.uuid)}`,
                data: data,
                headers: { 'Content-Type': 'application/vnd.tcpdump.pcap' },
            });
            // check if the file was sent successfully
            const response = await axios_1.default.get(`https://${PCAP_HOST}/api/v1/upload/${encodeURIComponent(config.email)}/${encodeURIComponent(name)}?key=${encodeURIComponent(this.publicKey)}&uuid=${encodeURIComponent(this.uuid)}`);
            if (response.status === 200 && response.data === md5) {
                if (name.endsWith('.pcap')) {
                    node_fs_1.default.unlinkSync(fileName);
                }
                this.log.debug(`[RSYNC] Sent file ${fileName}(${size2text(len)}) to the cloud: ${responsePost.status}`);
                this.log.debug(`[RSYNC] Datei ${fileName}(${size2text(len)}) an die Cloud gesendet: ${responsePost.status}`);
            }
            else {
                this.log.warn(`[RSYNC] File sent to server, but check fails. ${fileName} to the cloud: status=${responsePost.status}, len=${len}, response=${response.data}`);
                this.log.warn(`[RSYNC] Datei wurde zum Server gesendet, aber Prüfung war nicht erfolgreich. ${fileName} an die Cloud: status=${responsePost.status}, len=${len}, response=${response.data}`);
            }
        }
        catch (e) {
            this.log.error(`[RSYNC] Cannot send file ${fileName} to the cloud: ${e}`);
            this.log.error(`[RSYNC] Datei ${fileName} kann nicht zum Server geschickt werden: ${e}`);
        }
    }
    async startSynchronization() {
        if (this.context.terminate) {
            this.log.debug(`[RSYNC] Requested termination. No synchronization`);
            this.log.debug(`[RSYNC] Terminierung wurde angefragt. Keine Synchronisierung`);
            return;
        }
        // calculate the total number of bytes
        let totalBytes = 0;
        this.log.debug(`[RSYNC] Start synchronization...`);
        this.log.debug(`[RSYNC] Starte Synchronisierung...`);
        // calculate the total number of bytes in pcap files
        let pcapFiles;
        let allFiles;
        try {
            allFiles = node_fs_1.default.readdirSync(this.workingDir);
            pcapFiles = allFiles.filter(f => f.endsWith('.pcap'));
            for (const file of pcapFiles) {
                totalBytes += node_fs_1.default.statSync(`${this.workingDir}/${file}`).size;
            }
        }
        catch (e) {
            this.log.error(`[RSYNC] Cannot read working directory "${this.workingDir}" for sync : ${e}`);
            this.log.error(`[RSYNC] Arbeitsverzeichnis "${this.workingDir}" kann nicht für die Synchronisierung gelesen werden: ${e}`);
            return;
        }
        if (!totalBytes) {
            this.log.debug(`[RSYNC] No files to sync`);
            this.log.debug(`[RSYNC] Keine Dateien zum synchronisieren`);
            return;
        }
        if (this.syncRunning) {
            this.log.warn(`[RSYNC] Synchronization still running...`);
            this.log.warn(`[RSYNC] Synchronisierung läuft noch...`);
            return;
        }
        this.syncRunning = true;
        await this.setState('info.sync.running', true, true);
        this.log.debug(`[RSYNC] Syncing files to the cloud (${size2text(totalBytes)})`);
        this.log.debug(`[RSYNC] Dateien werden mit der Cloud Synchronisiert (${size2text(totalBytes)})`);
        // const cmd = this.getRSyncCommand();
        //
        // let error = '';
        //
        // this.log.debug(`[RSYNC] cmd: "${cmd}"`);
        //
        // this.syncProcess = exec(cmd, (_error, stdout, stderr) => {
        //     (stderr || _error) && this.log.warn(`[RSYNC] Error by synchronization: ${stderr}, ${_error}`);
        //     error = _error ? _error.message : '';
        // });
        //
        // this.syncProcess.on('error', (_error) => error = _error.message);
        //
        // this.syncProcess.on('exit', (code) => {
        //     this.syncProcess = null;
        //
        //     // delete all pcap files if no error
        //     if (!error && code === 0) {
        //         this.clearWorkingDir();
        //     }
        //
        //     if (this.syncRunning) {
        //         this.syncRunning = false;
        //         this.setState('info.syncRunning', false, true);
        //     }
        //
        //     if (this.saveAfterSync) {
        //         this.saveAfterSync = false;
        //         this.savePacketsToFile();
        //     }
        //
        //     if (code !== 0) {
        //         this.log.warn(`[RSYNC] Cannot sync files. rsync returned ${code}, error: ${error}`);
        //     } else {
        //         this.log.debug(`[RSYNC] Syncing files done with code ${code}`);
        //     }
        //
        //     if (cb) {
        //         cb();
        //     }
        // });
        // send files to the cloud
        // first send meta files
        for (let i = 0; i < allFiles.length; i++) {
            const file = allFiles[i];
            if (file.endsWith('.json')) {
                await this.sendOneFileToCloud(`${this.workingDir}/${file}`);
            }
        }
        // send all pcap files
        for (let i = 0; i < pcapFiles.length; i++) {
            const file = pcapFiles[i];
            await this.sendOneFileToCloud(`${this.workingDir}/${file}`);
        }
        this.syncRunning = false;
        await this.setState('info.sync.running', false, true);
    }
}
exports.KISSHomeResearchAdapter = KISSHomeResearchAdapter;
KISSHomeResearchAdapter.macCache = {};
if (require.main !== module) {
    // Export the constructor in compact mode
    module.exports = (options) => new KISSHomeResearchAdapter(options);
}
else {
    // otherwise start the instance directly
    (() => new KISSHomeResearchAdapter())();
}
//# sourceMappingURL=main.js.map
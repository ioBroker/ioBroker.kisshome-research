"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.KISSHomeResearchAdapter = void 0;
const adapter_core_1 = require("@iobroker/adapter-core");
const axios_1 = __importDefault(require("axios"));
const node_path_1 = require("node:path");
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const utils_1 = require("./lib/utils");
const recording_1 = require("./lib/recording");
const fritzbox_1 = require("./lib/fritzbox");
const PCAP_HOST = 'kisshome-experiments.if-is.net';
// save files every 60 minutes
const SAVE_DATA_EVERY_MS = 3600000;
// save files if bigger than 50 Mb
const SAVE_DATA_IF_BIGGER = 50 * 1024 * 1024;
const SYNC_INTERVAL = 3600000; // 3_600_000;
const BACKUP_KEYS = '0_userdata.0.kisshomeResearchKeys';
function size2text(size) {
    if (size < 1024) {
        return `${size} B`;
    }
    if (size < 1024 * 1024) {
        return `${Math.round((size * 10) / 1024) / 10} kB`;
    }
    return `${Math.round((size * 10) / (1024 * 1024) / 10)} MB`;
}
class KISSHomeResearchAdapter extends adapter_core_1.Adapter {
    constructor(options = {}) {
        super({
            ...options,
            name: 'kisshome-research',
            useFormatDate: true,
        });
        this.tempDir = '';
        this.uniqueMacs = [];
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
        this.IPs = [];
        const pack = JSON.parse((0, node_fs_1.readFileSync)((0, node_path_1.join)(__dirname, '..', 'package.json'), 'utf8'));
        this.versionPack = pack.version.replace(/\./g, '-');
        this.on('ready', () => this.onReady());
        this.on('unload', callback => this.onUnload(callback));
        this.on('message', this.onMessage.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
    }
    async onMessage(msg) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q;
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
                            if (((_a = msg.message) === null || _a === void 0 ? void 0 : _a.ip) || this.config.fritzbox) {
                                const users = await (0, fritzbox_1.getFritzBoxUsers)(((_b = msg.message) === null || _b === void 0 ? void 0 : _b.ip) || this.config.fritzbox);
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
                                (this.config.fritzbox && ((_d = msg.message) === null || _d === void 0 ? void 0 : _d.login)) ||
                                (this.config.login && ((_e = msg.message) === null || _e === void 0 ? void 0 : _e.password)) ||
                                this.config.password) {
                                const filter = await (0, fritzbox_1.getFritzBoxFilter)(((_f = msg.message) === null || _f === void 0 ? void 0 : _f.ip) || this.config.fritzbox, ((_g = msg.message) === null || _g === void 0 ? void 0 : _g.login) || this.config.login, ((_h = msg.message) === null || _h === void 0 ? void 0 : _h.password) || this.config.password);
                                this.sendTo(msg.from, msg.command, {
                                    text: filter
                                        ? this.language === 'de'
                                            ? 'Fritz!Box unterstützt Filter-Funktion'
                                            : 'Fritz!Box supports Filter-Feature'
                                        : this.language === 'de'
                                            ? 'Fritz!Box unterstützt Filter-Funktion nicht'
                                            : 'Fritz!Box does not support Filter-Feature',
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
                                (this.config.fritzbox && ((_k = msg.message) === null || _k === void 0 ? void 0 : _k.login)) ||
                                (this.config.login && ((_l = msg.message) === null || _l === void 0 ? void 0 : _l.password)) ||
                                this.config.password) {
                                const ifaces = await (0, fritzbox_1.getFritzBoxInterfaces)(((_m = msg.message) === null || _m === void 0 ? void 0 : _m.ip) || this.config.fritzbox, (_o = msg.message) === null || _o === void 0 ? void 0 : _o.login, (_p = msg.message) === null || _p === void 0 ? void 0 : _p.password, ((_q = msg.message) === null || _q === void 0 ? void 0 : _q.login) === this.config.login &&
                                    msg.message.password === this.config.password
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
                            const result = await this.getMacForIps(devices);
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
            if (this.language === 'de') {
                this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: Unbekannte E-Mail-Adresse`);
            }
            else {
                this.log.error(`Cannot register on the kisshome-cloud: Unknown email address`);
            }
        }
        else if (response.status === 403) {
            if (this.language === 'de') {
                this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: Der öffentliche Schlüssel hat sich geändert. Bitte kontaktieren Sie uns unter kisshome@internet-sicherheit.de`);
            }
            else {
                this.log.error(`Cannot register on the kisshome-cloud: public key changed. Please contact us via kisshome@internet-sicherheit.de`);
            }
            await this.registerNotification('kisshome-research', 'publicKey', 'Public key changed');
        }
        else if (response.status === 401) {
            if (this.language === 'de') {
                this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: Ungültiges Passwort`);
            }
            else {
                this.log.error(`Cannot register on the cloud: invalid password`);
            }
        }
        else if (response.status === 422) {
            if (this.language === 'de') {
                this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: E-Mail, öffentlicher Schlüssel oder UUID fehlen`);
            }
            else {
                this.log.error(`Cannot register on the cloud: missing email, public key or uuid`);
            }
        }
        else {
            if (this.language === 'de') {
                this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: ${response.data || response.statusText || response.status}`);
            }
            else {
                this.log.error(`Cannot register on the kisshome-cloud: ${response.data || response.statusText || response.status}`);
            }
        }
    }
    async onReady() {
        var _a, _b, _c, _d, _e, _f;
        const date = new Date();
        if (date.getFullYear() >= 2025 && date.getMonth() >= 4) {
            if (this.language === 'de') {
                this.log.error('Die Studie ist beendet. Danke für eure Teilnahme. Der Adapter beendet sich jetzt.');
            }
            else {
                this.log.error('The study is finished. Thank you for your participation. The adapter will terminate now.');
            }
            const obj = await this.getForeignObjectAsync(`system.adapter.${this.namespace}`);
            if (obj === null || obj === void 0 ? void 0 : obj.common) {
                obj.common.enabled = false;
                await this.setForeignObject(obj._id, obj);
            }
            return;
        }
        // read UUID
        const uuidObj = await this.getForeignObjectAsync('system.meta.uuid');
        if ((_a = uuidObj === null || uuidObj === void 0 ? void 0 : uuidObj.native) === null || _a === void 0 ? void 0 : _a.uuid) {
            this.uuid = uuidObj.native.uuid;
        }
        else {
            if (this.language === 'de') {
                this.log.error('Kann UUID nicht auslesen');
            }
            else {
                this.log.error('Cannot read UUID');
            }
            return;
        }
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
        if (!this.config.fritzbox) {
            if (this.language === 'de') {
                this.log.error(`Fritz!Box is nicht eingegeben`);
            }
            else {
                this.log.error(`Fritz!Box is not defined`);
            }
            return;
        }
        // try to get MAC addresses for all IPs
        this.IPs = this.config.devices.filter(item => item.enabled && (item.ip || item.mac) && item.ip !== this.config.fritzbox);
        const tasks = this.IPs.filter(ip => !ip.mac);
        let fritzMac = '';
        try {
            // determine the MAC of Fritzbox
            const fritzEntry = await this.getMacForIps([
                { ip: this.config.fritzbox, mac: '', enabled: true, desc: 'FritzBox', uuid: '1' },
            ]);
            fritzMac = ((_b = fritzEntry[0]) === null || _b === void 0 ? void 0 : _b.mac) || '';
        }
        catch {
            if (this.language === 'de') {
                this.log.debug(`Kann die MAC Adresse von FritzBox nicht finden`);
            }
            else {
                this.log.debug(`Cannot determine MAC addresses of Fritz!Box`);
            }
        }
        if (tasks.length) {
            try {
                const macs = await this.getMacForIps(tasks);
                for (let i = 0; i < tasks.length; i++) {
                    const mac = macs[i];
                    if (mac === null || mac === void 0 ? void 0 : mac.mac) {
                        const item = this.IPs.find(t => t.ip === mac.ip);
                        if (item) {
                            item.mac = mac.mac;
                        }
                    }
                }
                // print out the IP addresses without MAC addresses
                const missing = this.IPs.filter(item => !item.mac);
                if (missing.length) {
                    if (this.language === 'de') {
                        this.log.warn(`Für folgende IP konnten keine MAC Adressen gefunden werden: ${missing.map(t => t.ip).join(', ')}`);
                    }
                    else {
                        this.log.warn(`Cannot get MAC addresses for the following IPs: ${missing.map(t => t.ip).join(', ')}`);
                    }
                }
            }
            catch (e) {
                if (e.toString().includes('no results')) {
                    if (this.language === 'de') {
                        this.log.warn(`Für folgende IP könnten keine MAC Adressen gefunden: ${tasks.map(t => t.ip).join(', ')}`);
                    }
                    else {
                        this.log.warn(`Cannot get MAC addresses for the following IPs: ${tasks.map(t => t.ip).join(', ')}`);
                    }
                }
                else {
                    if (this.language === 'de') {
                        this.log.error(`MAC-Adressen können nicht ermittelt werden: ${e}`);
                    }
                    else {
                        this.log.error(`Cannot get MAC addresses: ${e}`);
                    }
                }
            }
        }
        // take only unique MAC addresses and not MAC of Fritzbox
        this.uniqueMacs = [];
        this.IPs.forEach(item => {
            var _a;
            return !this.uniqueMacs.includes(item.mac) &&
                ((_a = item.mac) === null || _a === void 0 ? void 0 : _a.trim()) &&
                item.mac !== fritzMac &&
                this.uniqueMacs.push(item.mac);
        });
        this.uniqueMacs = this.uniqueMacs.filter(mac => mac);
        // detect temp directory
        this.tempDir = this.config.tempDir || '/run/shm';
        if ((0, node_fs_1.existsSync)(this.tempDir)) {
            if (this.language === 'de') {
                this.log.info(`${this.tempDir} wird als temporäres Verzeichnis verwendet`);
            }
            else {
                this.log.info(`Using ${this.tempDir} as temporary directory`);
            }
        }
        else if ((0, node_fs_1.existsSync)('/run/shm')) {
            this.tempDir = '/run/shm';
            if (this.language === 'de') {
                this.log.info(`${this.tempDir} wird als temporäres Verzeichnis verwendet`);
            }
            else {
                this.log.info(`Using ${this.tempDir} as temporary directory`);
            }
        }
        else if ((0, node_fs_1.existsSync)('/tmp')) {
            this.tempDir = '/tmp';
            if (this.language === 'de') {
                this.log.info(`${this.tempDir} wird als temporäres Verzeichnis verwendet`);
            }
            else {
                this.log.info(`Using ${this.tempDir} as temporary directory`);
            }
        }
        else {
            if (this.language === 'de') {
                this.log.warn(`Es kann kein temporäres Verzeichnis gefunden werden. Bitte geben Sie es manuell in der Konfiguration an. Für beste Leistung sollte es eine RAM-Disk sein.`);
            }
            else {
                this.log.warn(`Cannot find any temporary directory. Please specify manually in the configuration. For best performance it should be a RAM disk`);
            }
            return;
        }
        this.tempDir = this.tempDir.replace(/\\/g, '/');
        if (this.tempDir.endsWith('/')) {
            this.tempDir = this.tempDir.substring(0, this.tempDir.length - 1);
        }
        let privateKey = '';
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
        if (!keysObj || !((_c = keysObj === null || keysObj === void 0 ? void 0 : keysObj.native) === null || _c === void 0 ? void 0 : _c.publicKey) || !((_d = keysObj.native) === null || _d === void 0 ? void 0 : _d.privateKey)) {
            // try to read the key on the address '0_userdata.0.kisshomeResearchPublicKey'
            let keysRestored = false;
            try {
                const keysState = await this.getForeignStateAsync(BACKUP_KEYS);
                if ((keysState === null || keysState === void 0 ? void 0 : keysState.val) && typeof keysState.val === 'string' && keysState.val.includes('/////')) {
                    const [_public, _private] = keysState.val.split('/////');
                    this.publicKey = _public;
                    privateKey = _private;
                    keysRestored = true;
                    if (this.language === 'de') {
                        this.log.info('Schlüssel wurde aus "0_userdata.0.kisshomeResearchKeys" wiederherstellt.');
                    }
                    else {
                        this.log.info('The keys were restored from "0_userdata.0.kisshomeResearchKeys".');
                    }
                }
            }
            catch {
                // ignore
            }
            if (!keysRestored) {
                if (this.language === 'de') {
                    this.log.info('Schlüssel werden erstmalig generiert.');
                }
                else {
                    this.log.info('Generating keys for the first time.');
                }
                const result = (0, utils_1.generateKeys)();
                privateKey = result.privateKey;
                this.publicKey = result.publicKey;
            }
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
            if (!keysRestored) {
                await this.saveKeyForUninstallAndInstall(this.publicKey, privateKey);
            }
        }
        else {
            privateKey = keysObj.native.privateKey;
            this.publicKey = keysObj.native.publicKey;
            await this.saveKeyForUninstallAndInstall(this.publicKey, privateKey, true);
        }
        if (!this.publicKey || !privateKey) {
            if (this.language === 'de') {
                this.log.error('Schlüssel können nicht generiert werden.');
            }
            else {
                this.log.error('Cannot generate keys.');
            }
            return;
        }
        this.workingDir = `${this.tempDir}/hourly_pcaps`;
        // create hourly directory
        try {
            if (!(0, node_fs_1.existsSync)(this.workingDir)) {
                (0, node_fs_1.mkdirSync)(this.workingDir);
            }
        }
        catch (e) {
            if (this.language === 'de') {
                this.log.error(`Arbeitsverzeichnis "${this.workingDir}" kann nicht erstellt werden: ${e}`);
            }
            else {
                this.log.error(`Cannot create working directory "${this.workingDir}": ${e}`);
            }
            return;
        }
        // this.clearWorkingDir();
        if (!this.config.email) {
            if (this.language === 'de') {
                this.log.error('Keine E-Mail angegeben. Bitte geben Sie eine E-Mail-Adresse in der Konfiguration an.');
                this.log.error('Sie müssen diese E-Mail zuerst unter https://kisshome-feldversuch.if-is.net/#register registrieren.');
            }
            else {
                this.log.error('No email provided. Please provide an email address in the configuration.');
                this.log.error('You must register this email first on https://kisshome-feldversuch.if-is.net/#register.');
            }
            return;
        }
        try {
            // register on the cloud
            const response = await axios_1.default.post(`https://${PCAP_HOST}/api/v1/registerKey`, {
                publicKey: this.publicKey,
                email: this.config.email,
                uuid: this.uuid,
            });
            if (response.status === 200) {
                if (((_e = response.data) === null || _e === void 0 ? void 0 : _e.command) === 'terminate') {
                    if (this.language === 'de') {
                        this.log.warn('Server hat die Terminierung des Adapters angefordert');
                    }
                    else {
                        this.log.warn('Server requested to terminate the adapter');
                    }
                    const obj = await this.getForeignObjectAsync(`system.adapter.${this.namespace}`);
                    if ((_f = obj === null || obj === void 0 ? void 0 : obj.common) === null || _f === void 0 ? void 0 : _f.enabled) {
                        obj.common.enabled = false;
                        await this.setForeignObjectAsync(obj._id, obj);
                    }
                }
                else {
                    if (this.language === 'de') {
                        this.log.info('Erfolgreich in der Cloud registriert');
                    }
                    else {
                        this.log.info('Successfully registered on the cloud');
                    }
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
                if (this.language === 'de') {
                    this.log.error(`Registrieren auf der kisshome-cloud nicht möglich: ${e}`);
                }
                else {
                    this.log.error(`Cannot register on the kisshome-cloud: ${e}`);
                }
            }
            return;
        }
        this.saveMetaFile();
        await this.setState('info.recording.running', false, true);
        await this.setState('info.recording.triggerWrite', false, true);
        if (!this.uniqueMacs.length) {
            if (this.language === 'de') {
                this.log.warn(`[PCAP] Keine MAC-Adressen für die Aufzeichnung angegeben. Bitte geben Sie einige MAC-Adressen oder IP-Adressen an, die in MAC-Adressen aufgelöst werden können`);
            }
            else {
                this.log.warn(`[PCAP] No any MAC addresses provided for recording. Please provide some MAC addresses or Ip addresses, that could be resolved to MAC address`);
            }
            return;
        }
        this.subscribeStates('info.recording.enabled');
        this.subscribeStates('info.recording.triggerWrite');
        this.recordingEnabled = ((await this.getStateAsync('info.recording.enabled')) || {}).val || false;
        if (this.recordingEnabled) {
            // start the monitoring
            this.startRecording().catch(e => {
                if (this.language === 'de') {
                    this.log.error(`[PCAP] Aufzeichnen kann nicht gestartet werden: ${e}`);
                }
                else {
                    this.log.error(`[PCAP] Cannot start recording: ${e}`);
                }
            });
            // Send the data every hour to the cloud
            this.syncJob();
        }
        else {
            if (this.language === 'de') {
                this.log.warn('Aufzeichnen ist nicht aktiviert. Nichts passiert.');
            }
            else {
                this.log.warn('Recording is not enabled. Do nothing.');
            }
        }
    }
    async saveKeyForUninstallAndInstall(publicKey, privateKey, check) {
        if (check) {
            // check if the key is already saved
            const keysState = await this.getForeignStateAsync(BACKUP_KEYS);
            if ((keysState === null || keysState === void 0 ? void 0 : keysState.val) === `${publicKey}/////${privateKey}`) {
                return;
            }
            if (keysState) {
                await this.setForeignStateAsync(BACKUP_KEYS, `${publicKey}/////${privateKey}`, true);
                return;
            }
        }
        // create state "0_userdata.0.kisshomeResearchKeys"
        await this.setForeignObjectAsync(BACKUP_KEYS, {
            type: 'state',
            common: {
                name: {
                    en: 'Keys for KISSHome adapter',
                    de: 'Schlüssel für KISSHome adapter',
                    ru: 'Ключи для адаптера KISSHome',
                    pt: 'Chaves para o adaptador KISSHome',
                    nl: 'Sleutels voor KISSHome-adapter',
                    fr: "Clés pour l'adaptateur KISSHome",
                    it: "Chiavi per l'adattatore KISSHome",
                    es: 'Claves para el adaptador KISSHome',
                    pl: 'Klucze dla adaptera KISSHome',
                    uk: 'Ключі для адаптера KISSHome',
                    'zh-cn': 'KISSHome适配器的密钥',
                },
                desc: {
                    en: 'It can be deleted if KISSHome adapter uninstalled and does not used anymore',
                    de: 'Es kann gelöscht werden, wenn der KISSHome-Adapter deinstalliert und nicht mehr verwendet wird',
                    ru: 'Его можно удалить, если адаптер KISSHome удален и больше не используется',
                    pt: 'Pode ser excluído se o adaptador KISSHome for desinstalado e não for mais usado',
                    nl: 'Het kan worden verwijderd als de KISSHome-adapter is verwijderd en niet meer wordt gebruikt',
                    fr: "Il peut être supprimé si l'adaptateur KISSHome est désinstallé et n'est plus utilisé",
                    it: "Può essere eliminato se l'adattatore KISSHome è disinstallato e non viene più utilizzato",
                    es: 'Se puede eliminar si se desinstala el adaptador KISSHome y ya no se usa',
                    pl: 'Można go usunąć, jeśli adapter KISSHome jest odinstalowany i nie jest już używany',
                    uk: 'Можна видалити, якщо адаптер KISSHome видалено і більше не використовується',
                    'zh-cn': '如果KISSHome适配器已卸载且不再使用，则可以删除它',
                },
                type: 'string',
                read: true,
                write: false,
                role: 'state',
            },
            native: {},
        });
        await this.setForeignStateAsync(BACKUP_KEYS, `${publicKey}/////${privateKey}`, true);
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
            if (this.language === 'de') {
                this.log.error(`[RSYNC] Kann nicht synchronisieren: ${e}`);
            }
            else {
                this.log.error(`[RSYNC] Cannot synchronize: ${e}`);
            }
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
                        this.startRecording().catch(e => {
                            if (this.language === 'de') {
                                this.log.error(`Aufzeichnen kann nicht gestartet werden: ${e}`);
                            }
                            else {
                                this.log.error(`Cannot start recording: ${e}`);
                            }
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
                        void this.setState('info.recording.triggerWrite', false, true).catch(e => this.language === 'de'
                            ? this.log.error(`Kann triggerWrite nicht setzten: ${e}`)
                            : this.log.error(`Cannot set triggerWrite: ${e}`));
                        this.savePacketsToFile();
                        setTimeout(() => {
                            this.startSynchronization().catch(e => {
                                if (this.language === 'de') {
                                    this.log.error(`[RSYNC] Kann nicht synchronisieren: ${e}`);
                                }
                                else {
                                    this.log.error(`[RSYNC] Cannot synchronize: ${e}`);
                                }
                            });
                        }, 2000);
                    }
                }
            }
        }
    }
    restartRecording() {
        this.startTimeout && clearTimeout(this.startTimeout);
        this.startTimeout = this.setTimeout(() => {
            this.startTimeout = undefined;
            this.startRecording().catch(e => {
                if (this.language === 'de') {
                    this.log.error(`Aufzeichnen kann nicht gestartet werden: ${e}`);
                }
                else {
                    this.log.error(`Cannot start recording: ${e}`);
                }
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
            const fd = (0, node_fs_1.openSync)(fileName, 'w');
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
                byteArray.writeUInt32LE(this.context.modifiedMagic || this.context.libpCapFormat ? MODIFIED_MAGIC : STANDARD_MAGIC, 0);
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
                (0, node_fs_1.writeSync)(fd, byteArray, 0, byteArray.length, 0);
                offset = byteArray.length;
            }
            for (let i = 0; i < packetsToSave.length; i++) {
                const packet = packetsToSave[i];
                (0, node_fs_1.writeSync)(fd, packet, 0, packet.length, offset);
                offset += packet.length;
            }
            (0, node_fs_1.closeSync)(fd);
            if (this.language === 'de') {
                this.log.debug(`Datei ${fileName} mit ${size2text(offset)} gespeichert`);
            }
            else {
                this.log.debug(`Saved file ${fileName} with ${size2text(offset)}`);
            }
        }
        this.context.lastSaved = Date.now();
    }
    calculateMd5(content) {
        const hash = (0, node_crypto_1.createHash)('md5');
        hash.update(content);
        return hash.digest('hex');
    }
    async startRecording() {
        if (!this.uniqueMacs.length) {
            if (this.language === 'de') {
                this.log.error(`[PCAP] Keine MAC-Adressen für die Aufzeichnung angegeben. Bitte geben Sie einige MAC-Adressen oder IP-Adressen an, die in MAC-Adressen aufgelöst werden können`);
            }
            else {
                this.log.error(`[PCAP] No any MAC addresses provided for recording. Please provide some MAC addresses or Ip addresses, that could be resolved to MAC address`);
            }
            return;
        }
        // take sid from fritzbox
        if (!this.sid || !this.sidCreated || Date.now() - this.sidCreated >= 3600000) {
            try {
                this.sid =
                    (await (0, fritzbox_1.getFritzBoxToken)(this.config.fritzbox, this.config.login, this.config.password, (text) => this.log.warn(text))) || '';
                this.sidCreated = Date.now();
            }
            catch (e) {
                this.sid = '';
                this.sidCreated = 0;
                if (this.language === 'de') {
                    this.log.error(`[PCAP] SID kann nicht von Fritz!Box abgerufen werden: ${e}`);
                }
                else {
                    this.log.error(`[PCAP] Cannot get SID from Fritz!Box: ${e}`);
                }
            }
        }
        if (this.sid) {
            if (this.language === 'de') {
                this.log.debug(`[PCAP] Nutze SID: ${this.sid}`);
            }
            else {
                this.log.debug(`[PCAP] Use SID: ${this.sid}`);
            }
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
            const response = await (0, recording_1.stopAllRecordingsOnFritzBox)(this.config.fritzbox, this.sid);
            if (response) {
                if (this.language === 'de') {
                    this.log.info(`[PCAP] Stopped all recordings on Fritz!Box: ${response}`);
                }
                else {
                    this.log.info(`[PCAP] Alle Aufnahmen auf der Fritz!Box wurden beendet: ${response}`);
                }
            }
            if (this.language === 'de') {
                this.log.debug(`[PCAP] Starte das Mitschneiden von ${this.config.fritzbox}/"${this.config.iface}"...`);
            }
            else {
                this.log.debug(`[PCAP] Starting recording on ${this.config.fritzbox}/"${this.config.iface}"...`);
            }
            this.log.debug(`[PCAP] ${(0, recording_1.getRecordURL)(this.config.fritzbox, this.sid, this.config.iface, this.uniqueMacs)}`);
            (0, recording_1.startRecordingOnFritzBox)(this.config.fritzbox, this.sid, this.config.iface, this.uniqueMacs, async (error) => {
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
                    this.restartRecording();
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
            if (this.language === 'de') {
                this.log.warn('[PCAP] Anmelden auf Fritz!Box nicht möglich. Vermutlich falsche Anmeldedaten oder die Fritz!Box ist nicht verfügbar.');
            }
            else {
                this.log.warn('[PCAP] Cannot login into Fritz!Box. Could be wrong credentials or Fritz!Box is not available');
            }
            // try to get the token in 10 seconds again. E.g., if fritzbox is rebooting
            this.restartRecording();
        }
    }
    static getTimestamp() {
        const now = new Date();
        return `${now.getUTCFullYear()}-${(now.getUTCMonth() + 1).toString().padStart(2, '0')}-${now.getUTCDate().toString().padStart(2, '0')}_${now.getUTCHours().toString().padStart(2, '0')}-${now.getUTCMinutes().toString().padStart(2, '0')}-${now.getUTCSeconds().toString().padStart(2, '0')}`;
    }
    saveMetaFile() {
        const text = KISSHomeResearchAdapter.getDescriptionFile(this.IPs);
        const newFile = `${this.workingDir}/${KISSHomeResearchAdapter.getTimestamp()}_v${this.versionPack}_meta.json`;
        try {
            // find the latest file
            let changed = false;
            let files = (0, node_fs_1.readdirSync)(this.workingDir);
            // sort descending
            files.sort((a, b) => b.localeCompare(a));
            // if two JSON files are coming after each other, the older one must be deleted
            for (let f = files.length - 1; f > 0; f--) {
                if (files[f].endsWith('_meta.json') && files[f - 1].endsWith('_meta.json')) {
                    (0, node_fs_1.unlinkSync)(`${this.workingDir}/${files[f]}`);
                    changed = true;
                }
            }
            // read the list anew as it was changed
            if (changed) {
                files = (0, node_fs_1.readdirSync)(this.workingDir);
                // sort descending
                files.sort((a, b) => b.localeCompare(a));
            }
            // find the latest file and delete all other _meta.json files
            const latestFile = files.find(f => f.endsWith('_meta.json'));
            // if existing meta file found
            if (latestFile) {
                // compare the content
                const oldFile = (0, node_fs_1.readFileSync)(`${this.workingDir}/${latestFile}`, 'utf8');
                if (oldFile !== text) {
                    if (this.language === 'de') {
                        this.log.debug('Meta-Datei aktualisiert');
                    }
                    else {
                        this.log.debug('Meta file updated');
                    }
                    // delete the old JSON file only if no pcap files exists
                    if (files[0].endsWith('_meta.json')) {
                        (0, node_fs_1.unlinkSync)(`${this.workingDir}/${latestFile}`);
                    }
                    (0, node_fs_1.writeFileSync)(newFile, text);
                    return newFile;
                }
                return `${this.workingDir}/${latestFile}`;
            }
            if (this.language === 'de') {
                this.log.info('Meta-Datei wurde angelegt.');
            }
            else {
                this.log.info('Meta file created');
            }
            // if not found => create new one
            (0, node_fs_1.writeFileSync)(newFile, text);
            return newFile;
        }
        catch (e) {
            if (this.language === 'de') {
                this.log.warn(`Speicher von Meta-Datei "${newFile}" nicht möglich: ${e}`);
            }
            else {
                this.log.warn(`Cannot save meta file "${newFile}": ${e}`);
            }
            return '';
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
    async getMacForIps(devices) {
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
                    else {
                        if (this.language === 'de') {
                            this.log.warn(`Kann die MAC Adresse von ${dev.ip} nicht auflösen`);
                        }
                        else {
                            this.log.warn(`Cannot resolve MAC address of ${dev.ip}`);
                        }
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
            // ignore
        }
    }
    clearWorkingDir() {
        try {
            const files = (0, node_fs_1.readdirSync)(this.workingDir);
            for (const file of files) {
                if (file.endsWith('.pcap')) {
                    try {
                        (0, node_fs_1.unlinkSync)(`${this.workingDir}/${file}`);
                    }
                    catch (e) {
                        if (this.language === 'de') {
                            this.log.error(`Die Datei ${this.workingDir}/${file} kann nicht gelöscht werden: ${e}`);
                        }
                        else {
                            this.log.error(`Cannot delete file ${this.workingDir}/${file}: ${e}`);
                        }
                    }
                }
                else if (!file.endsWith('.json')) {
                    // delete unknown files
                    try {
                        (0, node_fs_1.unlinkSync)(`${this.workingDir}/${file}`);
                    }
                    catch (e) {
                        if (this.language === 'de') {
                            this.log.error(`Die Datei ${this.workingDir}/${file} kann nicht gelöscht werden: ${e}`);
                        }
                        else {
                            this.log.error(`Cannot delete file ${this.workingDir}/${file}: ${e}`);
                        }
                    }
                }
            }
        }
        catch (e) {
            if (this.language === 'de') {
                this.log.error(`Arbeitsverzeichnis „${this.workingDir}“ kann nicht gelesen werden: ${e}`);
            }
            else {
                this.log.error(`Cannot read working directory "${this.workingDir}": ${e}`);
            }
        }
    }
    async sendOneFileToCloud(fileName, size) {
        var _a, _b;
        try {
            if (!(0, node_fs_1.existsSync)(fileName)) {
                if (this.language === 'de') {
                    this.log.warn(`[RSYNC] Datei "${fileName}" existiert nicht. Größe: ${size ? size2text(size) : 'unbekannt'}`);
                }
                else {
                    this.log.warn(`[RSYNC] File "${fileName}" does not exist. Size: ${size ? size2text(size) : 'unknown'}`);
                }
                return;
            }
            const data = (0, node_fs_1.readFileSync)(fileName);
            const name = (0, node_path_1.basename)(fileName);
            const len = data.length;
            const md5 = this.calculateMd5(data);
            // check if the file was sent successfully
            try {
                const responseCheck = await axios_1.default.get(`https://${PCAP_HOST}/api/v1/upload/${encodeURIComponent(this.config.email)}/${encodeURIComponent(name)}?key=${encodeURIComponent(this.publicKey)}&uuid=${encodeURIComponent(this.uuid)}`);
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
                        (0, node_fs_1.unlinkSync)(fileName);
                    }
                    return;
                }
            }
            catch {
                // ignore
            }
            const responsePost = await (0, axios_1.default)({
                method: 'post',
                url: `https://${PCAP_HOST}/api/v1/upload/${encodeURIComponent(this.config.email)}/${encodeURIComponent(name)}?key=${encodeURIComponent(this.publicKey)}&uuid=${encodeURIComponent(this.uuid)}`,
                data: data,
                headers: { 'Content-Type': 'application/vnd.tcpdump.pcap' },
            });
            // check if the file was sent successfully
            const response = await axios_1.default.get(`https://${PCAP_HOST}/api/v1/upload/${encodeURIComponent(this.config.email)}/${encodeURIComponent(name)}?key=${encodeURIComponent(this.publicKey)}&uuid=${encodeURIComponent(this.uuid)}`);
            if (response.status === 200 && response.data === md5) {
                if (name.endsWith('.pcap')) {
                    (0, node_fs_1.unlinkSync)(fileName);
                }
                if (this.language === 'de') {
                    this.log.debug(`[RSYNC] Datei ${fileName}(${size2text(len)}) an die Cloud gesendet (${size ? size2text(size) : 'unbekannt'}): ${responsePost.status}`);
                }
                else {
                    this.log.debug(`[RSYNC] Sent file ${fileName}(${size2text(len)}) to the cloud (${size ? size2text(size) : 'unbekannt'}): ${responsePost.status}`);
                }
            }
            else {
                if (this.language === 'de') {
                    this.log.warn(`[RSYNC] Datei wurde zum Server gesendet, aber Prüfung war nicht erfolgreich (${size ? size2text(size) : 'unbekannt'}). ${fileName} an die Cloud: status=${responsePost.status}, len=${len}, response=${response.data}`);
                }
                else {
                    this.log.warn(`[RSYNC] File sent to server, but check fails (${size ? size2text(size) : 'unbekannt'}). ${fileName} to the cloud: status=${responsePost.status}, len=${len}, response=${response.data}`);
                }
            }
        }
        catch (e) {
            if (this.language === 'de') {
                this.log.error(`[RSYNC] Datei ${fileName} kann nicht zum Server geschickt werden (${size ? size2text(size) : 'unbekannt'}): ${e}`);
            }
            else {
                this.log.error(`[RSYNC] Cannot send file ${fileName} to the cloud (${size ? size2text(size) : 'unbekannt'}): ${e}`);
            }
        }
    }
    async startSynchronization() {
        if (this.context.terminate) {
            if (this.language === 'de') {
                this.log.debug(`[RSYNC] Terminierung wurde angefragt. Keine Synchronisierung`);
            }
            else {
                this.log.debug(`[RSYNC] Requested termination. No synchronization`);
            }
            return;
        }
        // calculate the total number of bytes
        let totalBytes = 0;
        if (this.language === 'de') {
            this.log.debug(`[RSYNC] Starte Synchronisierung...`);
        }
        else {
            this.log.debug(`[RSYNC] Start synchronization...`);
        }
        // calculate the total number of bytes in pcap files
        let pcapFiles;
        let allFiles;
        const sizes = {};
        try {
            allFiles = (0, node_fs_1.readdirSync)(this.workingDir);
            pcapFiles = allFiles.filter(f => f.endsWith('.pcap'));
            for (const file of pcapFiles) {
                sizes[file] = (0, node_fs_1.statSync)(`${this.workingDir}/${file}`).size;
                totalBytes += sizes[file];
            }
        }
        catch (e) {
            if (this.language === 'de') {
                this.log.error(`[RSYNC] Arbeitsverzeichnis "${this.workingDir}" kann nicht für die Synchronisierung gelesen werden: ${e}`);
            }
            else {
                this.log.error(`[RSYNC] Cannot read working directory "${this.workingDir}" for sync : ${e}`);
            }
            return;
        }
        if (!totalBytes) {
            if (this.language === 'de') {
                this.log.debug(`[RSYNC] Keine Dateien zum synchronisieren`);
            }
            else {
                this.log.debug(`[RSYNC] No files to sync`);
            }
            return;
        }
        if (this.syncRunning) {
            if (this.language === 'de') {
                this.log.warn(`[RSYNC] Synchronisierung läuft noch...`);
            }
            else {
                this.log.warn(`[RSYNC] Synchronization still running...`);
            }
            return;
        }
        this.syncRunning = true;
        await this.setState('info.sync.running', true, true);
        if (this.language === 'de') {
            this.log.debug(`[RSYNC] Dateien werden mit der Cloud Synchronisiert (${size2text(totalBytes)})`);
        }
        else {
            this.log.debug(`[RSYNC] Syncing files to the cloud (${size2text(totalBytes)})`);
        }
        // send files to the cloud
        // first send meta files
        let sent = false;
        for (let i = 0; i < allFiles.length; i++) {
            const file = allFiles[i];
            if (file.endsWith('.json')) {
                await this.sendOneFileToCloud(`${this.workingDir}/${file}`);
                sent = true;
            }
        }
        if (!sent) {
            // create meta file anew and send it to the cloud
            const fileName = this.saveMetaFile();
            if (fileName) {
                await this.sendOneFileToCloud(fileName);
            }
            else if (this.language === 'de') {
                this.log.debug(`[RSYNC] Kann die META Datei nicht anlegen. Keine Synchronisierung`);
                return;
            }
            else {
                this.log.debug(`[RSYNC] Cannot create META file. No synchronization`);
                return;
            }
        }
        // send all pcap files
        for (let i = 0; i < pcapFiles.length; i++) {
            const file = pcapFiles[i];
            await this.sendOneFileToCloud(`${this.workingDir}/${file}`, sizes[file]);
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
import React from 'react';
import PropTypes from 'prop-types';

import {
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Checkbox, IconButton,
    TextField, LinearProgress, Fab,
} from '@mui/material';

import { Add, Delete } from '@mui/icons-material';

// important to make from package and not from some children.
// invalid
// import ConfigGeneric from '@iobroker/adapter-react-v5/ConfigGeneric';
// valid
import { ConfigGeneric } from '@iobroker/json-config';
import { i18n } from '@iobroker/adapter-react-v5';

const styles = {
    table: {
        minWidth: 400
    },
    header: {
        fontSize: 16,
        fontWeight: 'bold',
    },
    td: {
        padding: '2px 16px',
    },
};

async function browseHomekit(socket, instance) {
    const states = await socket.getObjectViewSystem('state', `${instance}.`, `${instance}.\u9999`);
    const devices = [];
    const ids = Object.keys(states).filter(id => id.endsWith('.address'));
    for (let i = 0; i < ids.length; i++) {
        const id = ids[i];
        const value = await socket.getState(id);
        if (value?.val) {
            devices.push({
                ip: value.val,
                name: 'homekit-controller',
            });
        }
    }

    return devices;
}

async function browseHomeConnect(socket, instance) {
    const states = await socket.getObjectViewSystem('state', `${instance}.`, `${instance}.\u9999`);
    const devices = [];
    // This must be found if it is address or not
    const ids = Object.keys(states).filter(id => id.endsWith('.address'));
    for (let i = 0; i < ids.length; i++) {
        const id = ids[i];
        const value = await socket.getState(id);
        if (value?.val) {
            devices.push({
                ip: value.val,
                name: 'homekit-controller',
            });
        }
    }

    return devices;
}

async function browseShelly(socket, instance) {
    const states = await socket.getObjectViewSystem('state', `${instance}.`, `${instance}.\u9999`);
    const devices = [];
    const ids = Object.keys(states).filter(id => id.endsWith('.hostname'));
    for (let i = 0; i < ids.length; i++) {
        const id = ids[i];
        const value = await socket.getState(id);
        if (value?.val) {
            devices.push({
                ip: value.val,
                name: 'shelly',
            });
        }
    }

    return devices;
}

async function browseClients(socket, instance) {
    const clients = await socket.getObjectViewSystem('state', `${instance}.info.clients.`, `${instance}.info.clients.\u9999`);
    const devices = [];
    const objs = Object.values(clients);
    for (let i = 0; i < objs.length; i++) {
        if (objs[i]?.native?.ip) {
            devices.push({
                ip: objs[i].native.ip,
                name: instance.split('.')[0],
            });
        }
    }
    return devices;
}

async function browseUpnp(socket, instance) {
    const objects = await socket.getObjectViewSystem('device', `${instance}.`, `${instance}.\u9999`);
    const objs = Object.values(objects);
    const devices = [];
    for (let i = 0; i < objs.length; i++) {
        if (objs[i]?.type === 'device' && objs[i]?.native?.ip) {
            devices.push({
                ip: objs[i].native.ip,
                name: instance.split('.')[0],
            });
        }
    }

    return devices;
}

const ADAPTERS = [
    { adapter: 'broadlink2', attr: 'additional' },
//     { adapter: 'cameras' },
    { adapter: 'harmony', attr: 'devices', arrayAttr: 'ip' },
    { adapter: 'hm-rpc', attr: 'homematicAddress' },
    // { adapter: 'hmip' }, not possible. It communicates with the cloud
    { adapter: 'homeconnect', browse: browseHomeConnect },
    { adapter: 'homekit-controller', attr: 'discoverIp', browse: browseHomekit },
    { adapter: 'hue', attr: 'bridge' },
    { adapter: 'knx', attr: 'bind' },
    { adapter: 'lgtv', attr: 'ip' },
    { adapter: 'loxone', attr: 'host' },
//    { adapter: 'meross' }, not possible. It communicates with the cloud
    { adapter: 'mihome-vacuum', attr: 'ip' },
    { adapter: 'modbus', attr: 'params.bind', clients: true },
    { adapter: 'mqtt', attr: 'url', clients: true }, // read clients IP addresses
    { adapter: 'mqtt-client', attr: 'host' },
    { adapter: 'lcn', attr: 'host' },
    { adapter: 'knx', attr: 'gwip' },
    { adapter: 'onvif' },
    { adapter: 'openknx', attr: 'gwip' },
    { adapter: 'broadlink2', attr: 'additional' },
    { adapter: 'proxmox', attr: 'ip' },
    { adapter: 'samsung', attr: 'ip' },
    { adapter: 'shelly', browse: browseShelly },
    { adapter: 'sonoff', clients: true },
    { adapter: 'sonos', attr: 'devices', arrayAttr: 'ip' },
    { adapter: 'tr-064', attr: 'iporhost' },
//    { adapter: 'tuya' }, not possible. It communicates with the cloud
    { adapter: 'unify', attr: 'controllerIp' },
    { adapter: 'upnp', browse: browseUpnp },
    { adapter: 'wled', attr: 'devices', arrayAttr: 'ip' },
    { adapter: 'wifilight', attr: 'devices', arrayAttr: 'ip' },
];

function validateMacAddress(mac) {
    if (!mac) {
        return true;
    }
    if (typeof mac !== 'string') {
        return false;
    }
    mac = mac.trim().toUpperCase().replace(/\s/g, '');
    if (!mac) {
        return true;
    }
    if (mac.match(/^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$/)) {
        return true;
    }
    return !!mac.match(/^([0-9A-F]{12})$/);
}

function normalizeMacAddress(mac) {
    if (!validateMacAddress(mac)) {
        return mac;
    }
    mac = mac.toUpperCase().trim().replace(/[\s:-]/g, '');
    // convert to 00:11:22:33:44:55
    return mac.replace(/(..)(..)(..)(..)(..)(..)/, '$1:$2:$3:$4:$5:$6');
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
    const parts = ip.trim().split('.').map(part => parseInt(part, 10));
    return !parts.find(part => part < 0 || part > 0xFF);
}

function normalizeIpAddress(ip) {
    if (!validateIpAddress(ip)) {
        return ip;
    }
    const parts = ip.trim().split('.');
    return parts.map(part => parseInt(part, 10)).join('.');
}

class ConfigCustomInstancesSelector extends ConfigGeneric {
    async componentDidMount() {
        super.componentDidMount();

        let address = [];
        // get own ip address
        const config = await this.props.socket.getObject(`system.adapter.kisshome-research.${this.props.instance}`);
        if (config?.common.host) {
            const host = await this.props.socket.getObject(`system.host.${config.common.host}`);
            address = host.common.address;
        }

        let instances = await this.props.socket.getAdapterInstances();
        instances = instances
            .filter(instance =>
                instance?.common?.adminUI && (instance.common.adminUI.config !== 'none' || instance.common.adminUI.tab))
            .map(instance => ({
                id: instance._id.replace(/^system\.adapter\./, ''),
                name: instance.common.name,
                native: instance.native,
            }))
            .sort((a, b) => a.id > b.id ? 1 : (a.id < b.id ? -1 : 0));

        const ips = await this.collectIpAddresses(instances, address);

        const newState = {
            instances,
            ips,
        };

        // get vendor and MAC-Address information
        if (this.props.alive) {
            const devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
            newState.runningRequest = true;

            this.props.socket.sendTo(`kisshome-research.${this.props.instance}`, 'getMacForIps', devices)
                .then(result => {
                    // result: { result: { mac: string; vendor?: string, ip: string }[] }
                    let changedState = false;
                    const vendors = {};
                    result?.result?.forEach(item => {
                        const ip = item.ip;
                        const pos = ips.findIndex(i => i.ip === ip);
                        if (pos !== -1) {
                            changedState = true;
                            ips[pos].mac = item.mac;
                            vendors[item.mac] = item.vendor;
                        }
                    });

                    let changed = false;
                    // detect changed MAC addresses in saved information
                    devices.forEach(item => {
                        const pos = ips.findIndex(i => i.ip === item.ip);
                        if (pos !== -1) {
                            if (item.mac !== ips[pos].mac) {
                                changed = true;
                            }
                            if (!vendors[item.mac]) {
                                vendors[item.mac] = ips[pos].vendor;
                                changedState = true;
                            }
                        }
                    });

                    if (changedState) {
                        this.setState({ ips, vendors, runningRequest: false });
                    } else {
                        this.setState({ runningRequest: false });
                    }
                    if (changed) {
                        this.onChange('devices', devices);
                    }
                })
                .catch(e => {
                    if (e.toString() !== 'no results') {
                        window.alert(`Cannot get MAC addresses: ${e}`);
                    }
                    this.setState({ runningRequest: false });
                });
        }

        this.setState(newState);
    }

    static getAttr(obj, attr) {
        if (Array.isArray(attr)) {
            const name = attr.shift();
            if (typeof obj[name] === 'object') {
                return ConfigCustomInstancesSelector.getAttr(obj[name], attr);
            }

            return !attr.length ? obj[name] : null;
        }

        return ConfigCustomInstancesSelector.getAttr(obj, attr.split('.'));
    }

    static isIp(ip) {
        if (typeof ip === 'string') {
            if (ip.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                return 'ipv4';
            }
            if (ip.match(/^[\da-fA-F:]+$/)) {
                return 'ipv6';
            }
        }
        return null;
    }

    componentWillUnmount() {
        super.componentWillUnmount();
        this.validateTimeout && clearTimeout(this.validateTimeout);
        this.validateTimeout = null;
    }

    validateAddresses() {
        this.validateTimeout && clearTimeout(this.validateTimeout);

        this.validateTimeout = setTimeout(() => {
            this.validateTimeout = null;
            // read MACs for all IPs
        }, 1000);
    }

    async collectIpAddresses(instances, ownAddresses) {
        let result = [];

        instances = instances || this.state.instances;
        for (let i = 0; i < instances.length; i++) {
            const adapter = ADAPTERS.find(item => item.adapter === instances[i].name);
            if (adapter && instances[i].native) {
                const attr = adapter.attr;
                if (adapter.attr && instances[i].native[attr]) {
                    if (adapter.arrayAttr) {
                        if (Array.isArray(instances[i].native[attr])) {
                            for (let j = 0; j < instances[i].native[attr].length; j++) {
                                const item = instances[i].native[attr][j];
                                const ip = ConfigCustomInstancesSelector.getAttr(item, adapter.arrayAttr);
                                const type = ConfigCustomInstancesSelector.isIp(ip);
                                if (type) {
                                    result.push({
                                        ip,
                                        type,
                                        desc: instances[i].name,
                                    });
                                }
                            }
                        }
                    } else {
                        const ip = ConfigCustomInstancesSelector.getAttr(instances[i].native, attr);
                        const type = ConfigCustomInstancesSelector.isIp(ip);
                        if (type) {
                            result.push({
                                ip,
                                type,
                                desc: instances[i].name,
                            });
                        }
                    }
                }

                if (adapter.browse) {
                    try {
                        const devices = await adapter.browse(this.props.socket, instances[i]._id.replace('system.adapter.', ''));
                        devices.forEach(item => {
                            const type = ConfigCustomInstancesSelector.isIp(item.ip);
                            if (type) {
                                result.push({
                                    ip: item.ip,
                                    type,
                                    desc: item.name || instances[i].name,
                                });
                            }
                        });
                    } catch (e) {
                        console.error(`Cannot collect "${instances[i]}": ${e}`);
                    }
                }

                if (adapter.clients) {
                    try {
                        const devices = await browseClients(this.props.socket, instances[i]._id.replace('system.adapter.', ''));
                        devices.forEach(item => {
                            const type = ConfigCustomInstancesSelector.isIp(item.ip);
                            if (type) {
                                result.push({
                                    ip: item.ip,
                                    type,
                                    desc: item.name || instances[i].name,
                                });
                            }
                        });
                    } catch (e) {
                        console.error(`Cannot collect "${instances[i]}": ${e}`);
                    }
                }
            } else {
                 // check common settings like host, ip, address
                if (instances[i].native.ip &&
                    typeof instances[i].native.ip === 'string' &&
                    // Check if it IP4 address
                    instances[i].native.ip.match(/^\d+\.\d+\.\d+\.\d+$/)
                ) {
                    result.push({
                        ip: instances[i].native.ip,
                        type: 'ipv4',
                        desc: instances[i].name,
                    });
                } else if (instances[i].native.host &&
                    typeof instances[i].native.host === 'string' &&
                    // Check if it IP4 address
                    instances[i].native.host.match(/^\d+\.\d+\.\d+\.\d+$/)
                ) {
                    result.push({
                        ip: instances[i].native.host,
                        type: 'ipv4',
                        desc: instances[i].name,
                    });
                }
            }
        }

        result = result.filter(item =>
            !ownAddresses.includes(item.ip) &&
            item.ip !== '0.0.0.0' &&
            item.ip !== 'localhost' &&
            item.ip !== '127.0.0.1' &&
            item.ip !== '::1' &&
            item.type === 'ipv4' // take only ipv4 addresses
        );

        // filter duplicates
        const unique = [];
        for (let i = 0; i < result.length; i++) {
            if (!unique.find(item => item.ip === result[i].ip)) {
                unique.push(result[i]);
            }
        }

        return unique;
    }

    renderItem(error, disabled, defaultValue) {
        /** @type {{mac: string; ip: string; desc: string; enabled: boolean}[]} */
        const devices = ConfigGeneric.getValue(this.props.data, 'devices') || [];

        const notFound = this.state.ips ?
            devices.filter(iItem => !this.state.ips.find(item => item.ip === iItem.ip)) :
            devices;

        const allEnabled = devices.every(item => item.enabled) &&
            (this.state.ips ? this.state.ips.every(item => devices.find(iItem => iItem.ip === item.ip)) : true);

        return <TableContainer>
            {this.state.runningRequest ? <LinearProgress /> : <div style={{ height: 2, width: '100%' }} />}
            <Table style={styles.table} size="small">
                <TableHead>
                    <TableRow>
                        <TableCell style={{ ...styles.header, width: 120 }}>
                            <Checkbox
                                title={allEnabled ? i18n.t('custom_kisshome_unselect_all') : i18n.t('custom_kisshome_select_all')}
                                checked={allEnabled}
                                indeterminate={!allEnabled && devices.length > 0}
                                disabled={this.state.runningRequest}
                                onClick={() => {
                                    const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                    if (allEnabled) {
                                        _devices.forEach(item => item.enabled = false);
                                        for (let i = _devices.length - 1; i >= 0; i--) {
                                            if (this.state.ips.find(item => item.ip === _devices[i].ip)) {
                                                _devices.splice(i, 1);
                                            }
                                        }
                                    } else {
                                        _devices.forEach(item => item.enabled = true);
                                        this.state.ips.forEach(item => {
                                            if (!_devices.find(iItem => item.ip === iItem.ip)) {
                                                _devices.push({ ip: item.ip, mac: item.mac, desc: item.desc, enabled: true });
                                            }
                                        });
                                        _devices.forEach(item => item.enabled = true);
                                    }
                                    this.onChange('devices', _devices);
                                }}
                            />
                            <Fab
                                onClick={() => {
                                    const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                    _devices.push({ ip: '0.0.0.0', mac: '', desc: '', enabled: true });
                                    this.onChange('devices', _devices);
                                }}
                                size="small"
                                disabled={this.state.runningRequest}
                            >
                                <Add />
                            </Fab>
                        </TableCell>
                        <TableCell style={styles.header}>{i18n.t('custom_kisshome_ip')}</TableCell>
                        <TableCell style={styles.header}>{i18n.t('custom_kisshome_mac')}</TableCell>
                        <TableCell style={styles.header}>{i18n.t('custom_kisshome_vendor')}</TableCell>
                        <TableCell style={styles.header}>{i18n.t('custom_kisshome_name')}</TableCell>
                        <TableCell style={styles.header} />
                    </TableRow>
                </TableHead>
                <TableBody>
                    {this.state.ips?.map((row, i) => <TableRow key={i}>
                        <TableCell scope="row" style={styles.td}>
                            <Checkbox
                                checked={!!devices.find(item => item.ip === row.ip)?.enabled}
                                disabled={this.state.runningRequest}
                                onClick={() => {
                                    const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                    const pos = _devices.findIndex(item => item.ip === row.ip);
                                    if (pos === -1) {
                                        _devices.push({ ip: row.ip, mac: row.mac, desc: row.desc, enabled: true });
                                    } else {
                                        _devices.splice(pos, 1);
                                    }
                                    this.onChange('devices', _devices);
                                }}
                            />
                        </TableCell>
                        <TableCell style={styles.td}>{row.ip}</TableCell>
                        <TableCell style={styles.td}>{row.mac || ''}</TableCell>
                        <TableCell style={styles.td}>{this.state.vendors?.[row.mac] || ''}</TableCell>
                        <TableCell style={styles.td}>{row.desc}</TableCell>
                        <TableCell style={styles.td} />
                    </TableRow>)}
                    {notFound.map((row, i) => <TableRow key={i}>
                        <TableCell scope="row" style={styles.td}>
                            <Checkbox
                                checked={!!devices.find(item => item.ip === row.ip)?.enabled}
                                disabled={this.state.runningRequest}
                                onClick={() => {
                                    const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                    _devices[i].enabled = !_devices[i].enabled;
                                    this.onChange('devices', _devices);
                                }}
                            />
                        </TableCell>
                        <TableCell style={styles.td}>
                            <TextField
                                fullWidth
                                error={!validateIpAddress(row.ip)}
                                value={row.ip}
                                disabled={this.state.runningRequest}
                                onChange={e => {
                                    const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                    _devices[i].ip = e.target.value;
                                    this.onChange('devices', _devices);
                                    this.validateAddresses();
                                }}
                                onBlur={() => {
                                    if (row.ip.trim()) {
                                        const normalized = normalizeIpAddress(row.ip);
                                        if (normalized !== row.ip) {
                                            const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                            _devices[i].ip = normalized;
                                            this.onChange('devices', _devices);
                                        }
                                    }
                                }}
                                variant="standard"
                            />
                        </TableCell>
                        <TableCell style={styles.td}>
                            <TextField
                                fullWidth
                                value={row.mac}
                                disabled={this.state.runningRequest}
                                error={!validateMacAddress(row.mac)}
                                onChange={e => {
                                    const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                    _devices[i].mac = e.target.value;
                                    this.onChange('devices', _devices);
                                    this.validateAddresses();
                                }}
                                onBlur={() => {
                                    if (row.mac.trim()) {
                                        const normalized = normalizeMacAddress(row.mac);
                                        if (normalized !== row.mac) {
                                            const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                            _devices[i].mac = normalized;
                                            this.onChange('devices', _devices);
                                        }
                                    }
                                }}
                                variant="standard"
                            />
                        </TableCell>
                        <TableCell style={styles.td}>{this.state.vendors?.[normalizeMacAddress(row.mac)] || ''}</TableCell>
                        <TableCell style={styles.td}>
                            <TextField
                                fullWidth
                                value={row.desc}
                                disabled={this.state.runningRequest}
                                onChange={e => {
                                    const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                    _devices[i].desc = e.target.value;
                                    this.onChange('devices', _devices);
                                }}
                                variant="standard"
                            />
                        </TableCell>
                        <TableCell style={styles.td}>
                            <IconButton
                                disabled={this.state.runningRequest}
                                onClick={() => {
                                    const _devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                                    _devices.splice(i, 1);
                                    this.onChange('devices', _devices);
                                }}
                            >
                                <Delete />
                            </IconButton>
                        </TableCell>
                    </TableRow>)}
                </TableBody>
            </Table>
        </TableContainer>;
    }
}

ConfigCustomInstancesSelector.propTypes = {
    socket: PropTypes.object.isRequired,
    themeType: PropTypes.string,
    themeName: PropTypes.string,
    style: PropTypes.object,
    data: PropTypes.object.isRequired,
    schema: PropTypes.object,
    onError: PropTypes.func,
    onChange: PropTypes.func,
};

export default ConfigCustomInstancesSelector;

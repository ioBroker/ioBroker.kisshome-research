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

const ADAPTERS = [
    { adapter: 'alexa-2' },
    { adapter: 'broadlink2', attr: 'additional' },
//     { adapter: 'cameras' },
    { adapter: 'harmony', attr: 'devices', arrayAttr: 'ip' },
    { adapter: 'hm-rpc', attr: 'homematicAddress' },
    // { adapter: 'hmip' }, not possible. It communicates with the cloud
    { adapter: 'homeconnect' },
    { adapter: 'homekit-controller', attr: 'discoverIp' },
    { adapter: 'hue', attr: 'bridge' },
    { adapter: 'knx', attr: 'bind' },
    { adapter: 'lgtv', attr: 'ip' },
    { adapter: 'loxone', attr: 'host' },
//    { adapter: 'meross' }, not possible. It communicates with the cloud
    { adapter: 'mihome-vacuum', attr: 'ip' },
    { adapter: 'modbus', attr: 'params.bind' },
    { adapter: 'mqtt', attr: 'bind' },
    { adapter: 'mqtt-client', attr: 'host' },
    { adapter: 'onvif' },
    { adapter: 'openknx', attr: 'gwip' },
    { adapter: 'proxmox', attr: 'ip' },
    { adapter: 'samsung', attr: 'ip' },
    { adapter: 'shelly', attr: 'bind' },
    { adapter: 'sonoff', attr: 'bind' },
    { adapter: 'sonos', attr: 'devices', arrayAttr: 'ip' },
    { adapter: 'tr-064', attr: 'iporhost' },
//    { adapter: 'tuya' }, not possible. It communicates with the cloud
    { adapter: 'unify', attr: 'controllerIp' },
    { adapter: 'upnp' },
    { adapter: 'wled', attr: 'devices', arrayAttr: 'ip' },
];

function validateMacAddress(mac) {
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

        this.props.socket.getAdapterInstances()
            .then(instances => {
                instances = instances
                    .filter(instance =>
                        instance?.common?.adminUI && (instance.common.adminUI.config !== 'none' || instance.common.adminUI.tab))
                    .map(instance => ({
                        id: instance._id.replace(/^system\.adapter\./, ''),
                        name: instance.common.name,
                        native: instance.native,
                    }))
                    .sort((a, b) => a.id > b.id ? 1 : (a.id < b.id ? -1 : 0));

                const ips = this.collectIpAddresses(instances, address);

                const newState = {
                    instances,
                    ips,
                };
                // get vendor and MAC-Address information
                if (this.props.alive) {
                    const devices = [...(ConfigGeneric.getValue(this.props.data, 'devices') || [])];
                    const addresses = ips.map(item => item.ip);
                    // add to detected IPs the IPs from saved configuration
                    devices.forEach(item => {
                        if (!addresses.includes(item.ip)) {
                            addresses.push(item.ip);
                        }
                    });
                    newState.runningRequest = true;

                    this.props.socket.sendTo(`kisshome-research.${this.props.instance}`, 'getMacForIps', addresses)
                        .then(result => {
                            let changedState = false;
                            const vendors = {};
                            result.forEach(item => {
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
            });
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

    collectIpAddresses(instances, ownAddresses) {
        let result = [];

        instances = instances || this.state.instances;
        for (let i = 0; i < instances.length; i++) {
            const adapter = ADAPTERS.find(item => item.adapter === instances[i].name);
            if (adapter && instances[i].native) {
                const attr = adapter.attr;
                if (instances[i].native[attr]) {
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
            }
        }

        result = result.filter(item =>
            !ownAddresses.includes(item.ip) &&
            item.ip !== '0.0.0.0' &&
            item.ip !== 'localhost' &&
            item.ip !== '127.0.0.1' &&
            item.ip !== '::1'
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
                                checked={devices.includes(row.ip)}
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

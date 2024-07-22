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
    TextField, LinearProgress,
} from '@mui/material';

import { Delete } from '@mui/icons-material';

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
                    const instanceIPs = [...(ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [])];
                    const addresses = ips.map(item => item.ip);
                    // add to detected IPs the IPs from saved configuration
                    instanceIPs.forEach(item => {
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
                            instanceIPs.forEach(item => {
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
                                this.onChange('instanceIPs', instanceIPs);
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
        const instanceIPs = ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [];

        const notFound = this.state.ips ?
            instanceIPs.filter(iItem => !this.state.ips.find(item => item.ip === iItem.ip)) :
            instanceIPs;

        const allEnabled = instanceIPs.every(item => item.enabled) &&
            (this.state.ips ? this.state.ips.every(item => instanceIPs.find(iItem => iItem.ip === item.ip)) : true);

        return <TableContainer>
            {this.state.runningRequest ? <LinearProgress /> : <div style={{ height: 2, width: '100%' }} />}
            <Table style={styles.table} size="small">
                <TableHead>
                    <TableRow>
                        <TableCell style={styles.header}>
                            <Checkbox
                                title={allEnabled ? i18n.t('custom_kisshome_unselect_all') : i18n.t('custom_kisshome_select_all')}
                                checked={allEnabled}
                                indeterminate={!allEnabled && instanceIPs.length > 0}
                                onClick={() => {
                                    const _instanceIPs = [...(ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [])];
                                    if (allEnabled) {
                                        _instanceIPs.forEach(item => item.enabled = false);
                                        for (let i = _instanceIPs.length - 1; i >= 0; i--) {
                                            if (this.state.ips.find(item => item.ip === _instanceIPs[i].ip)) {
                                                _instanceIPs.splice(i, 1);
                                            }
                                        }
                                    } else {
                                        _instanceIPs.forEach(item => item.enabled = true);
                                        this.state.ips.forEach(item => {
                                            if (!_instanceIPs.find(iItem => item.ip === iItem.ip)) {
                                                _instanceIPs.push({ ip: item.ip, mac: item.mac, desc: item.desc, enabled: true });
                                            }
                                        });
                                        _instanceIPs.forEach(item => item.enabled = true);
                                    }
                                    this.onChange('instanceIPs', _instanceIPs);
                                }}
                            />
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
                                checked={!!instanceIPs.find(item => item.ip === row.ip)?.enabled}
                                onClick={() => {
                                    const _instanceIPs = [...(ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [])];
                                    const pos = _instanceIPs.findIndex(item => item.ip === row.ip);
                                    if (pos === -1) {
                                        _instanceIPs.push({ ip: row.ip, mac: row.mac, desc: row.desc, enabled: true });
                                    } else {
                                        _instanceIPs.splice(pos, 1);
                                    }
                                    this.onChange('instanceIPs', _instanceIPs);
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
                                checked={instanceIPs.includes(row.ip)}
                                onClick={() => {
                                    const _instanceIPs = [...(ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [])];
                                    _instanceIPs[i].enabled = !_instanceIPs[i].enabled;
                                    this.onChange('instanceIPs', _instanceIPs);
                                }}
                            />
                        </TableCell>
                        <TableCell style={styles.td}>
                            <TextField
                                fullWidth
                                value={row.ip}
                                onChange={e => {
                                    const _instanceIPs = [...(ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [])];
                                    _instanceIPs[i].ip = e.target.value;
                                    this.onChange('instanceIPs', _instanceIPs);
                                }}
                                variant="standard"
                            />
                        </TableCell>
                        <TableCell style={styles.td}>
                            <TextField
                                fullWidth
                                value={row.mac}
                                onChange={e => {
                                    const _instanceIPs = [...(ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [])];
                                    _instanceIPs[i].mac = e.target.value;
                                    this.onChange('instanceIPs', _instanceIPs);
                                }}
                                variant="standard"
                            />
                        </TableCell>
                        <TableCell style={styles.td}>{this.state.vendors?.[row.mac] || ''}</TableCell>
                        <TableCell style={styles.td}>
                            <TextField
                                fullWidth
                                value={row.desc}
                                onChange={e => {
                                    const _instanceIPs = [...(ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [])];
                                    _instanceIPs[i].desc = e.target.value;
                                    this.onChange('instanceIPs', _instanceIPs);
                                }}
                                variant="standard"
                            />
                        </TableCell>
                        <TableCell style={styles.td}>
                            <IconButton
                                onClick={() => {
                                    const _instanceIPs = [...(ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [])];
                                    _instanceIPs.splice(i, 1);
                                    this.onChange('instanceIPs', _instanceIPs);
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

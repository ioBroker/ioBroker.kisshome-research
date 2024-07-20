import React from 'react';
import PropTypes from 'prop-types';

import {
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Checkbox,
}  from '@mui/material';

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

                this.setState({ instances, ips });
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
                                        name: instances[i].name,
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
                                name: instances[i].name,
                            });
                        }
                    }
                }
            }
        }

        result = result.filter(item =>
            !ownAddresses.includes(item.ip) ||
            item.ip === '0.0.0.0' ||
            item.ip === 'localhost' ||
            item.ip === '127.0.0.1'
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
        if (!this.state.ips) {
            return null;
        }
        const instanceIPs = ConfigGeneric.getValue(this.props.data, 'instanceIPs') || [];

        return <TableContainer>
            <Table style={styles.table} size="small">
                <TableHead>
                    <TableRow>
                        <TableCell style={styles.header}>{i18n.t('custom_kisshome_enabled')}</TableCell>
                        <TableCell style={styles.header}>{i18n.t('custom_kisshome_ip')}</TableCell>
                        <TableCell style={styles.header}>{i18n.t('custom_kisshome_name')}</TableCell>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {this.state.ips.map((row, i) => <TableRow key={row.id}>
                        <TableCell scope="row" style={styles.td}>
                            <Checkbox
                                checked={instanceIPs.includes(row.ip)}
                                onClick={() => {
                                    const _instanceIPs = [...instanceIPs];
                                    const pos = _instanceIPs.indexOf(row.ip);
                                    if (pos !== -1) {
                                        _instanceIPs.splice(pos, 1);
                                    } else {
                                        _instanceIPs.push(row.ip);
                                        _instanceIPs.sort();
                                    }
                                    this.onChange('instanceIPs', _instanceIPs);
                                }}
                            />
                        </TableCell>
                        <TableCell style={styles.td}>{row.ip}</TableCell>
                        <TableCell style={styles.td}>{row.name}</TableCell>
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

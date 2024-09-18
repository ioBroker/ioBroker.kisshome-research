import axios from 'axios';
import crypto from 'node:crypto';

const KNOWN_INTERFACES: Record<string, boolean> = {
    ':acc0': true, //	27,2 MB
    ':acc0.4': true, //	4,5 KB
    'l2sd0.2': true, //	76,7 KB
    l2sm0: false, //	0 Bytes
    acc0: true, //	23,1 KB
    'acc0.4': false, //	0 Bytes
    eth0: true, //	182 KB
    eth1: true, //	0 Bytes
    eth2: true, //	186 KB
    eth3: true, //	0 Bytes
    eth_udma0: true, //	137 KB
    lan: true, //	not tested
    ppptty: false, //	0 Bytes
    traceDH0: true, //	3,5 MB
    traceDH2: true, //	30,7 KB
    traceDL0: true, //	264 KB
    traceDL2: true, //	15,5 KB
    traceN0: true, //	766 KB
    traceV0: true, //	382 KB
    traceV1: true, //	37,8 KB
    vlan_master0: true, //	241 KB
    wifi0: true, //	0 KB
    wifi1: true, //	0 KB
};

export async function getFritzBoxInterfaces(
    ip: string,
    login?: string,
    password?: string,
    sid?: string,
): Promise<{ label: string; value: string }[] | null> {
    if (!sid && login && password) {
        sid = (await getFritzBoxToken(ip, login, password, console.log)) || '';
    }
    if (!sid) {
        return null;
    }

    const response = await axios(`http://${ip}/capture.lua?sid=${sid}`);

    if (response.data) {
        let text = response.data;
        const result: { label: string; value: string }[] = [];
        // <tr>
        //    <th>1. Internetverbindung</th>
        //    <td class="buttonrow">
        //        <button type="submit" name="start" id="uiStart_1" value="2-1">Start</button>
        //    </td>
        //    <td class="imgcol" id="uiImage_1"></td>
        //    <td class="buttonrow"><button type="submit" name="stop" id="uiStop_1" value="2;1;ptm0">Stopp</button></td>
        // </tr>
        let i = text.indexOf('<th>');
        while (i !== -1) {
            text = text.substring(i);
            const tr = text.indexOf('</tr>');
            if (tr !== -1) {
                const part = text.substring(0, tr);
                text = text.substring(tr);

                const nameStart = part.indexOf('name="start"');
                const nameStop = part.indexOf('>Start<');
                if (nameStart !== -1 && nameStop !== -1) {
                    const name = part.substring(nameStart, nameStop);
                    const m = name.match(/value="([^"]+)"/);
                    const label = part.match(/<th>([^<]+)<\/th>/);
                    if (m) {
                        result.push({ label: label ? `${label[1]} - ${m[1]}` : m[1], value: m[1] });
                    }
                }
            } else {
                break;
            }
            i = text.indexOf('<th>');
        }

        return result.filter(e => KNOWN_INTERFACES[e.value] === undefined || KNOWN_INTERFACES[e.value]);
    }

    return null;
}

export async function getFritzBoxFilter(
    ip: string,
    login?: string,
    password?: string,
    sid?: string,
): Promise<boolean | null> {
    if (!sid && login && password) {
        sid = (await getFritzBoxToken(ip, login, password, console.log)) || '';
    }
    if (!sid) {
        return null;
    }

    const response = await axios(`http://${ip}/capture.lua?sid=${sid}`);
    if (response.data) {
        return response.data.includes('id="uiFilter"');
    }
    return null;
}

export async function getFritzBoxUsers(ip: string): Promise<string[]> {
    const response = await axios(`http://${ip}/login_sid.lua`);
    if (response.data) {
        const challenge = response.data.match(/<User( [a-z]+="\w+")?>([^<]+)<\/User>/g);
        return challenge
            .map((user: string) => {
                const res = user.match(/>([^<]+)<\/User>/);
                return res ? res[1] : null;
            })
            .filter((user: string) => user);
    }
    return [];
}

export async function getFritzBoxToken(
    ip: string,
    login: string,
    password: string,
    log: (text: string) => void,
): Promise<string | null> {
    try {
        const response = await axios(`http://${ip.trim()}/login_sid.lua`);
        if (response.data) {
            const challenge = response.data.match(/<Challenge>(.*?)<\/Challenge>/);
            if (challenge) {
                const challengeResponse = `${challenge[1]}-${password.trim()}`;
                const challengeResponseBuffer = Buffer.from(challengeResponse, 'utf16le');
                const challengeResponseHash = crypto.createHash('md5').update(challengeResponseBuffer).digest('hex');
                const response2 = await axios(
                    `http://${ip.trim()}/login_sid.lua?username=${(login || 'dslf-config').trim()}&response=${challenge[1]}-${challengeResponseHash}`,
                );
                if (response2.data) {
                    const sessionInfo = response2.data.match(/<SID>(.*?)<\/SID>/);
                    if (sessionInfo) {
                        if (sessionInfo[1] === '0000000000000000') {
                            log(`Invalid Fritz!Box password for user ${(login || 'dslf-config').trim()}`);
                            log(`Ungueltiges Fitz!Box Passwort fuer den Nutzer ${(login || 'dslf-config').trim()}`);
                        }
                        return sessionInfo[1] !== '0000000000000000' ? sessionInfo[1] : null;
                    }
                }
            }
        }
    } catch (e) {
        console.error(e);
        log(`Error while getting token: ${e.message}`);
        log(`Fehler beim Erhalten eines Token: ${e.message}`);
        return null;
    }

    return null;
}

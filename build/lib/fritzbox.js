"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getFritzBoxInterfaces = getFritzBoxInterfaces;
exports.getFritzBoxFilter = getFritzBoxFilter;
exports.getFritzBoxUsers = getFritzBoxUsers;
exports.getFritzBoxToken = getFritzBoxToken;
const axios_1 = __importDefault(require("axios"));
const node_crypto_1 = __importDefault(require("node:crypto"));
async function getFritzBoxInterfaces(ip, login, password, sid) {
    if (!sid && login && password) {
        sid = (await getFritzBoxToken(ip, login, password, console.log)) || '';
    }
    if (!sid) {
        return null;
    }
    const response = await (0, axios_1.default)(`http://${ip}/capture.lua?sid=${sid}`);
    if (response.data) {
        let text = response.data;
        const result = [];
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
            }
            else {
                break;
            }
            i = text.indexOf('<th>');
        }
        return result;
    }
    return null;
}
async function getFritzBoxFilter(ip, login, password, sid) {
    if (!sid && login && password) {
        sid = (await getFritzBoxToken(ip, login, password, console.log)) || '';
    }
    if (!sid) {
        return null;
    }
    const response = await (0, axios_1.default)(`http://${ip}/capture.lua?sid=${sid}`);
    if (response.data) {
        return response.data.includes('id="uiFilter"');
    }
    return null;
}
async function getFritzBoxUsers(ip) {
    const response = await (0, axios_1.default)(`http://${ip}/login_sid.lua`);
    if (response.data) {
        const challenge = response.data.match(/<User( [a-z]+="\w+")?>([^<]+)<\/User>/g);
        return challenge
            .map((user) => {
            const res = user.match(/>([^<]+)<\/User>/);
            return res ? res[1] : null;
        })
            .filter((user) => user);
    }
    return [];
}
async function getFritzBoxToken(ip, login, password, log) {
    try {
        const response = await (0, axios_1.default)(`http://${ip.trim()}/login_sid.lua`);
        if (response.data) {
            const challenge = response.data.match(/<Challenge>(.*?)<\/Challenge>/);
            if (challenge) {
                const challengeResponse = `${challenge[1]}-${password.trim()}`;
                const challengeResponseBuffer = Buffer.from(challengeResponse, 'utf16le');
                const challengeResponseHash = node_crypto_1.default.createHash('md5').update(challengeResponseBuffer).digest('hex');
                const response2 = await (0, axios_1.default)(`http://${ip.trim()}/login_sid.lua?username=${(login || 'dslf-config').trim()}&response=${challenge[1]}-${challengeResponseHash}`);
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
    }
    catch (e) {
        console.error(e);
        log(`Error while getting token: ${e.message}`);
        log(`Fehler beim Erhalten eines Token: ${e.message}`);
        return null;
    }
    return null;
}
//# sourceMappingURL=fritzbox.js.map
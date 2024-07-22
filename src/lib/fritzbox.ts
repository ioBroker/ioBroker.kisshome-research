import axios from 'axios';
import crypto from 'node:crypto';

export async function getFritzBoxInterfaces(ip: string, login: string, password: string) {

}

export async function getFritzBoxToken(ip: string, login: string, password: string) {
    try {
        const response = await axios(`http://${ip}/login_sid.lua`);
        if (response.data) {
            const challenge = response.data.match(/<Challenge>(.*?)<\/Challenge>/);
            if (challenge) {
                const challengeResponse = `${challenge[1]}-${password}`;
                const challengeResponseBuffer = Buffer.from(challengeResponse, 'utf16le');
                const challengeResponseHash = crypto.createHash('md5').update(challengeResponseBuffer).digest('hex');
                const response2 = await axios(`http://${ip}/login_sid.lua?username=${login}&response=${challengeResponseHash}`);
                if (response2.data) {
                    const sessionInfo = response2.data.match(/<SID>(.*?)<\/SID>/);
                    if (sessionInfo) {
                        return sessionInfo[1] !== '0000000000000000' ? sessionInfo[1] : null;
                    }
                }
            }
        }
    } catch (e) {
        console.error(e);
        return null;
    }

    return null;
}

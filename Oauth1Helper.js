const crypto = require('crypto');
const oauth1a = require('oauth-1.0a');

const CONSUMERKEY = process.env.CONSUMERKEY;
const CONSUMERSECRET = process.env.CONSUMERSECRET;
const TOKENKEY = process.env.TOKENKEY;
const TOKENSECRET = process.env.TOKENSECRET;

class Oauth1Helper {
    static getAuthHeaderForRequest(request) {
        const oauth = oauth1a({
            consumer: { key: CONSUMERKEY, secret: CONSUMERSECRET },
            signature_method: 'HMAC-SHA1',
            hash_function(base_string, key) {
                return crypto
                    .createHmac('sha1', key)
                    .update(base_string)
                    .digest('base64')
            },
        })

        const authorization = oauth.authorize(request, {
            key: TOKENKEY,
            secret: TOKENSECRET,
        });

        return oauth.toHeader(authorization);
    }
}

module.exports = Oauth1Helper;
// Lamda Authorizer Auth0 function
// This function is used to authorize the user based on the token provided by the client
// The function will return the policy document that will allow or deny access to the client

// Load jwt libraries
require('dotenv').config({ silent: true });

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const util = require('util');

const client = jwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: 'https://dev-tutojssyjl6gkfar.us.auth0.com/.well-known/jwks.json'
});

const getSigningKey = util.promisify(client.getSigningKey);

const getPolicyDocument = (effect, resource) => {
    return {
        Version: '2012-10-17',
        Statement: [{
            Action: 'execute-api:Invoke',
            Effect: effect,
            Resource: resource,
        }]
    };
};

const getToken = (params) => {
    if (!params.type || params.type !== 'TOKEN') {
        throw new Error('Expected "event.type" parameter to have value "TOKEN"');
    }

    const tokenString = params.authorizationToken;
    if (!tokenString) {
        throw new Error('Expected "event.authorizationToken" parameter to be set');
    }

    const match = tokenString.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) {
        throw new Error(`Invalid Authorization token - ${tokenString} does not match "Bearer .*"`);
    }
    return match[1];
};

exports.handler = async function (event, context) {
    console.log("Received event:", JSON.stringify(event, null, 2));

    try {
        const token = getToken(event);
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded || !decoded.header || !decoded.header.kid) {
            throw new Error('Invalid token');
        }

        const key = await getSigningKey(decoded.header.kid);
        const signingKey = key.publicKey || key.rsaPublicKey;

        const jwtOptions = {
            audience: 'https://dev-tutojssyjl6gkfar.us.auth0.com/api/v2/',
            issuer: 'https://dev-tutojssyjl6gkfar.us.auth0.com/',
            algorithms: ['RS256']
        };

        const verifiedToken = jwt.verify(token, signingKey, jwtOptions);
        console.log("Token verified successfully:", verifiedToken);

        context.succeed({
            principalId: verifiedToken.sub,
            policyDocument: getPolicyDocument('Allow', event.methodArn),
            context: { scope: verifiedToken.scope }
        });

    } catch (err) {
        console.error("Token verification failed:", err);
        context.fail('Unauthorized');
    }
};

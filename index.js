// Lamda Authorizer Auth0 function
// This function is used to authorize the user based on the token provided by the client
// The function will return the policy document that will allow or deny access to the client

// Load jwt libraries
require('dotenv').config();
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
});
function getKey(header, callback) {
    client.getSigningKey(header.kid, function (err, key) {
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
}

exports.handler = async function (event, context) {
    // Check if the token is provided
    if (!event.authorizationToken) {
        return context.fail('Unauthorized');
    }
    const generatePolicy = (principalId, effect, resource) => {
        const authResponse = {};
        authResponse.principalId = principalId;
        if (effect && resource) {
            const policyDocument = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Action: 'execute-api:Invoke',
                        Effect: effect,
                        Resource: resource
                    }
                ]
            };
            authResponse.policyDocument = policyDocument;
        }
        return authResponse;
    }
    const token = event.authorizationToken.replace('Bearer ', '');
    try {
        const decode = await jwt.verify(token, getKey, {
            audience: process.env.AUTH0_AUDIENCE,
            issuer: `https://${process.env.AUTH0_DOMAIN}/`,
            algorithms: ['RS256']
        });

        return generatePolicy(decode.sub, 'Allow', event.methodArn);
    } catch (error) {
        return generatePolicy('user', 'Deny', event.methodArn);
    }

}
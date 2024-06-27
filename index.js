// Lamda Authorizer Auth0 function
// This function is used to authorize the user based on the token provided by the client
// The function will return the policy document that will allow or deny access to the client

// Load jwt libraries
require('dotenv').config();
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
    jwksUri: `https://dev-tutojssyjl6gkfar.us.auth0.com/.well-known/jwks.json`
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, function (err, key) {
        if (err) {
            console.error("Error getting signing key:", err);
            callback(err);
        } else {
            const signingKey = key.publicKey || key.rsaPublicKey;
            callback(null, signingKey);
        }
    });
}

exports.handler = async function (event, context) {
    console.log("Received event:", JSON.stringify(event, null, 2));

    if (!event.authorizationToken) {
        console.error("No authorization token found in the request");
        context.fail('Unauthorized');
        return;
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
    };

    const token = event.authorizationToken.replace('Bearer ', '');
    jwt.verify(token, getKey, {
        audience: `https://dev-tutojssyjl6gkfar.us.auth0.com/api/v2/`,
        issuer: `https://dev-tutojssyjl6gkfar.us.auth0.com/`,
        algorithms: ['RS256']
    }, (err, decoded) => {
        if (err) {
            console.error("Token verification failed:", err);
            context.fail('Unauthorized');
        } else {
            console.log("Token verified successfully:", decoded);
            context.succeed(generatePolicy(decoded.sub, 'Allow', event.methodArn));
        }
    });
};
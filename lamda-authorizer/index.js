// Lamda Authorizer Auth0 function
// This function is used to authorize the user based on the token provided by the client
// The function will return the policy document that will allow or deny access to the client

// Load jwt libraries
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
    jwksUri: `https://dev-tutojssyjl6gkfar.us.auth0.com/.well-known/jwks.json`
});

async function getKey(header, callback) {
    let retries = 3;
    while (retries > 0) {
        try {
            const key = await client.getSigningKey(header.kid);
            const signingKey = key.publicKey || key.rsaPublicKey;
            console.log("Obtained signing key:", signingKey);
            return callback(null, signingKey);
        } catch (error) {
            if (error.code === 'ECONNRESET' && retries > 0) {
                console.warn(`TLS connection reset, retrying (${retries} attempts left)`);
                retries--;
                await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second before retrying
            } else {
                console.error("Error getting signing key:", error);
                return callback(error);
            }
        }
    }
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
        console.log("Generated Policy:", JSON.stringify(authResponse, null, 2));
        return authResponse;
    };

    const token = event.authorizationToken.replace('Bearer ', '');
    console.log("Verifying token:", token);
    jwt.verify(token, getKey, {
        audience: `https://dev-tutojssyjl6gkfar.us.auth0.com/api/v2/`,
        issuer: `https://dev-tutojssyjl6gkfar.us.auth0.com/`,
        algorithms: ['RS256']
    }, (err, decoded) => {
        if (err) {
            console.error("Token verification failed with error:", err);
            context.fail('Unauthorized');
        } else {
            console.log("Token verified successfully:", decoded);
            const policy = generatePolicy(decoded.sub, 'Allow', event.methodArn);
            console.log("Returning policy:", JSON.stringify(policy, null, 2));
            context.succeed(policy);
        }
    });
};

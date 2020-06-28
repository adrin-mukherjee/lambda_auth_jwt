const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');
const { promisify } = require("util");

const MSG_UNAUTHORIZED = "Unauthorized";
const MSG_INCORRECT_CRED_FORMAT = "Incorrect secret object format";

exports.handler = async(event)=>{

    const REGION_CODE = process.env.REGION_CODE || "ap-south-1"; 
    const CLIENTID_LOOKUP_PREFIX = process.env.CLIENTID_LOOKUP_PREFIX || "";
    const HEADER_AUTH = 'Authorization'; 
    const HEADER_CLIENTID = 'x-client-id'; 
    const SECRET_STRING = 'SecretString';
    const CONTEXT_BASIC_CRED_PARAM = "basic_credentials";

    console.log("Event >> ", event);

    var headers = event.headers;
    if(headers[HEADER_CLIENTID] && headers[HEADER_AUTH]){
        let clientID = headers[HEADER_CLIENTID];
        console.log("Client ID >> ", clientID);
        try{
            let token = headers[HEADER_AUTH];
            let response = {};
            
            let {key, credentials} = 
                await validateClientID(REGION_CODE, CLIENTID_LOOKUP_PREFIX + clientID)
                    .then(function(data) {
                        console.log("validateClientID- Response received from SecretsManager");  
                        if (SECRET_STRING in data) {
                            let secret = data.SecretString;
                            let secretString = JSON.parse(secret);
                            // Check secretString format
                            console.log("validateClientID- Validating secret object format");
                            if(!(secretString && secretString.key && secretString.credentials)){
                                throw MSG_INCORRECT_CRED_FORMAT;
                            }
                            return secretString;
                        }
                        else{
                            throw "SecretString not present";
                        }    
                    })
                    .catch(function(err) {
                        console.log("Error >> " + err.code + " >> " + err);
                        throw err;
                    });

            await jwtValidator(token, key)
                    .then((decoded)=>{
                        console.log("Decoded JWT token >> ", decoded);
                        response = generate_iam_policy(decoded.userid, 'Allow', event.methodArn);
                    })
                    .catch((err)=>{
                        throw err;
                    });
            let basic_auth_value = 'Basic ' + Buffer.from(credentials.username 
                                        + ":" 
                                        + credentials.password)
                                    .toString("base64");
            response.context = {};
            response.context[CONTEXT_BASIC_CRED_PARAM]= basic_auth_value; // Set the friendly name to response context
            console.log("Response >> ",response);
            return response;
        }
        catch(err){
            console.error("Error >> ", err);
            throw MSG_UNAUTHORIZED;
        }

    }
    else{
        console.error("Error >> Required HTTP headers are not present in the request");
        throw MSG_UNAUTHORIZED;
    }
};

// secret-object = {key: "<secret key>", basic_creds: {username: "<uname>", password: "<passwd>"}}
var validateClientID = async (region_code, clientID)=>{
    let request = new AWS.SecretsManager({region: region_code}).getSecretValue({SecretId: clientID}); 
    console.log("validateClientID- AWS request prepared");
    return request.promise();
};

var jwtValidator = async(token, key)=>{ 
    const BEARER = "bearer ";  // Authorization type/scheme = Bearer 
   
    if(token && token.toLowerCase().startsWith(BEARER)){
        token = token.substring(BEARER.length); // extract JWT token      
        const jwtverify = promisify(jwt.verify);
        return jwtverify(token, key, { algorithm: 'HS256'});
    }
    else{
        console.error("Error >> Invalid Bearer token");
        throw MSG_UNAUTHORIZED;
    }
};

var generate_iam_policy = (principal, effect, resource)=>{
    let response = {};
    response.principalId = principal;
    
    let policyDocument = generate_policy_doc(effect, resource);
    response.policyDocument = policyDocument;
    return response;
};

var generate_policy_doc = (effect, resource)=>{
    let policyDocument = {};
    policyDocument.Version = '2012-10-17'; 
    policyDocument.Statement = [];

    let statementOne = {};
    statementOne.Action = 'execute-api:Invoke'; 
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    return policyDocument;
};

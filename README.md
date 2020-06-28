# lambda_auth_jwt
### A sample lambda authorizer that expects two HTTP header parameters: *x-client-id* and *Authorization*.
- x-client-id is expected to carry a pre-determined client identifier
- Authorization is expected to carry a 'Bearer' JWT token signed by a secret key

### Here is what the authorizer does-
- Lookup client identifier (passed in x-client-id header) in Secrets Manager to fetch two pieces of information : 
  - Credentials to be used with API back-end call in the form of Basic AuthN 
  - Secret key to validate JWT token
- Validate Authorization Bearer (JWT) token using the secret key
- Prepare Basic AuthN header value from the credentials with Base64 encoding
- Create an IAM policy document with a response context to pass Basic AuthN header value to the back-end

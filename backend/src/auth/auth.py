import json
from site import abs_paths
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'dev-at9n1xil.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'kahawaApp'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implementeyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IndrcF9uMkNneV9qUW1BbWJGWDRvMSJ9.eyJpc3MiOiJodHRwczovL2Rldi1hdDluMXhpbC51cy5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NjJjYmZlNDFmZWNkMzIwODI3ZmQxMWIwIiwiYXVkIjoia2FoYXdhQXBwIiwiaWF0IjoxNjU3NTY0NTc0LCJleHAiOjE2NTc1NzE3NzIsImF6cCI6ImZQNmY3WDlUbkNpZjNEd2hSTWJGdFBtVmtpSUhWUXVoIiwic2NvcGUiOiIiLCJwZXJtaXNzaW9ucyI6WyJnZXQ6ZHJpbmtzIiwiZ2V0OmRyaW5rcy1kZXRhaWwiXX0.hGJtwptme_JttemdqUfc2_i9AldFw-C98l5N1jcIWfHaOKOgTvdhS_AFUZ34i4JK-0_u92i42fjwbI9kEi4GH8h2n8o0JcWkwALUOlvWrNT0g4JTf418v-z02yFYWGcVwZU00OBMv-rdJxQnsMD1VAgAnZs_4SuO3vLvZC_p_SK42KSawC23EHrSZ7ReSMwtTlNfPmnP0iAJJDK9jhzjzvZ8JWDca6pFmkQ0TNs5S3Llqr7DSuLf6HAeIzNfohiNfA64Uc8QQsnmr-ZrGZ73VM7i8FyN8MtqprZp5kvjjfzyIk41tEksyl-dLc-cyha4q_cs_QNQzOAqF8KAcs0GNg get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
    #raise Exception('Not Implemented')
    #Case: No Authorization header included
    if 'Authorization' not in request.headers:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Authorisation header not in token.'
        }, 401)
    
    auth_header_array = request.headers['authorization'].split(' ')

    #Case: Header not in correct format i.e 'Bearer your-token'
    if len(auth_header_array) != 2:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Authorisation header not formatted correctly.'
        }, 401)
    elif auth_header_array[0].upper() != 'BEARER':
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Authorisation header does not include Bearer.'
        }, 401)

    #Case: Correct authorization header present in JWT
    return auth_header_array[1]

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    #Case: JWT payload does not include permissions for role
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'Invalid_claims',
            'description': 'Permissions not in token'
        }, 400)

    #Case: Permission to perform task not found for role
    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'Forbidden',
            'description': 'Permission not found'
        }, 403)
    
    #Case: Permission found
    return True

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    #Public key
    url = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(url.read())

    #Choose key from header
    jwt_unverified_header = jwt.get_unverified_header(token)

    rsa_key = {}
    if 'kid' not in jwt_unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == jwt_unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    
    #Validating the token using keys if key found in unverified header
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )
            #payload needed later to check permissions
            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    else:
        raise AuthError({
                    'code': 'invalid_header',
                    'description': 'Unable to find the appropriate key.'
                }, 400)
    

'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
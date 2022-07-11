/* @TODO replace with your variables
 * ensure all variables on this page match your project
 */

export const environment = {
  production: false,
  apiServerUrl: 'http://127.0.0.1:5000', // the running FLASK api server url
  auth0: {
    url: 'dev-at9n1xil.us', // the auth0 domain prefix
    audience: 'kahawaApp', // the audience set for the auth0 app
    clientId: 'fP6f7X9TnCif3DwhRMbFtPmVkiIHVQuh', // the client id generated for the auth0 app
    callbackURL: 'http://127.0.0.1:8100', // the base url of the running ionic application. 
  }
};

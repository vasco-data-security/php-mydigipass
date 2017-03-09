<?php
/**
 * Copyright (c) 2010 VZnet Netzwerke Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author    Bastian Hofmann <bhfomann@vz.net>
 * @copyright 2010 VZnet Netzwerke Ltd.
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */
class OAuth2_Service_Configuration {

    const AUTHORIZATION_METHOD_HEADER = 1;
    const AUTHORIZATION_METHOD_ALTERNATIVE = 2;

    /**
     * @var string
     */
    private $_authorizeEndpoint;

    /**
     * @var string
     */
    private $_accessTokenEndpoint;

    /**
     * @var string
     */
    private $_authorizationMethod = self::AUTHORIZATION_METHOD_HEADER;

    /**
     * @param string $authorizeEndpoint
     * @param string $accessTokenEndpoint
     */
    public function __construct($authorizeEndpoint, $accessTokenEndpoint) {
        $this->_authorizeEndpoint = $authorizeEndpoint;
        $this->_accessTokenEndpoint = $accessTokenEndpoint;
    }

    /**
     * @return string
     */
    public function getAuthorizeEndpoint() {
        return $this->_authorizeEndpoint;
    }

    /**
     * @return string
     */
    public function getAccessTokenEndpoint() {
        return $this->_accessTokenEndpoint;
    }

    /**
     * @return string
     */
    public function setAuthorizationMethod($authorizationMethod) {
        $this->_authorizationMethod = $authorizationMethod;
    }

    /**
     * @return string
     */
    public function getAuthorizationMethod() {
        return $this->_authorizationMethod;
    }

}

class OAuth2_Service {

    /**
     * @var OAuth2_Client
     */
    private $_client;

    /**
     * @var OAuth2_Service_Configuration
     */
    private $_configuration;

    /**
     * @var OAuth2_DataStore_Interface
     */
    private $_dataStore;

    /**
     * @var string
     */
    private $_scope;
    private $_uuid;
    private $_headers;

    /**
     * @param OAuth2_Client $client
     * @param OAuth2_Service_Configuration $configuration
     * @param OAuth2_DataStore_Interface $dataStore
     * @param string $scope optional
     */
    public function __construct(OAuth2_Client $client, OAuth2_Service_Configuration $configuration, OAuth2_DataStore_Interface $dataStore, $scope = null) {
        $this->_client = $client;
        $this->_configuration = $configuration;
        $this->_dataStore = $dataStore;
        $this->_scope = $scope;
    }

    public function getUserData($base_uri, $access_token = null) {

        if (!isset($access_token)) {
            $token = $this->_dataStore->retrieveAccessToken();
            $access_token = $token->getAccessToken();
        }
        $headers = array('Authorization: Bearer ' . $access_token);
        $uri = $base_uri . '/oauth/user_data';
        $http = new OAuth2_HttpClient($uri, 'GET', "", $headers);
        $http->setDebug(true);
        $http->execute();
        $headers = $http->getHeaders();
        $type = 'text';

        if (isset($headers['Content-Type']) && strpos($headers['Content-Type'], 'application/json') !== false) {
            $type = 'json';
        }


        switch ($type) {
            case 'json':
                $response = json_decode($http->getResponse(), true);
                break;
            case 'text':
            default:
                $response = OAuth2_HttpClient::parseStringToArray($http->getResponse(), '&', '=');
                break;
        }
        $this->uuid = $response['uuid'];
        $_SESSION['uuid'] = $response['uuid'];
        $_SESSION['user'] = $response;
        return $response;
    }

    public function connectUser($url, $uuid = null) {
        if (!isset($uuid)) {
            $uuid = $_SESSION['uuid'];
        }
        if (!isset($uuid)) {
            throw new Exception("Could not retrieve the UUID from teh calls");
        }

        $parameters = json_encode(array(
            'uuids' => array($uuid),
        ));

        $url = $url . "/api/uuids/connected";

        //Initialize the connection
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $parameters);
        curl_setopt($ch, CURLOPT_HEADER, 1);        
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen($parameters)
        ));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_USERPWD, $this->_client->getClientKey() . ":" . $this->_client->getClientSecret());

        //IMPORTANT//
        //Remove the lower line when going live or testing your certificates
        //This line will make sure that the curl does not verify the SSL certificate
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

        $fullResponse = curl_exec($ch);
        if (FALSE === $fullResponse) {
            throw new Exception(curl_error($ch), curl_errno($ch));
        }
        $this->_info = curl_getinfo($ch);

        $this->_response = substr($fullResponse, $this->_info['header_size'], strlen($fullResponse));
        if ($this->_response === false) {
            $this->_response = '';
        }
        $headers = rtrim(substr($fullResponse, 0, $this->_info['header_size']));

        $this->_headers = OAuth2_HttpClient::parseStringToArray($headers, PHP_EOL, ':');
        if (isset($this->_headers['Status']) && strpos($this->_headers['Status'], '201') !== false) {
            return "Successful connected!";
        }

        return $fullResponse;
    }

    /**
     * redirect to authorize endpoint of service
     */
    public function authorize() {
        $parameters = array(
            'type' => 'web_server',
            'client_id' => $this->_client->getClientKey(),
            'redirect_uri' => $this->_client->getCallbackUrl(),
            'response_type' => 'code',
        );
        if ($this->_scope) {
            $parameters['scope'] = $this->_scope;
        }
        $url = $this->_configuration->getAuthorizeEndpoint();
        $url .= (strpos($url, '?') !== false ? '&' : '?') . http_build_query($parameters);

        header('Location: ' . $url);
    }

    /**
     * get access token of from service, has to be called after successful authorization
     *
     * @param string $code optional, if no code given method tries to get it out of $_GET
     */
    public function getAccessToken($code = null) {
        if (!isset($code)) {
            $code = $this->_dataStore->retrieveAuthToken();
        }
        if (!isset($code)) {
            throw new OAuth2_Exception('could not retrieve code out of callback request and no code given');
        }

        $parameters = array(
            'grant_type' => 'authorization_code',
            'type' => 'web_server',
            'client_id' => $this->_client->getClientKey(),
            'client_secret' => $this->_client->getClientSecret(),
            'redirect_uri' => $this->_client->getCallbackUrl(),
            'code' => $code,
        );
        if ($this->_scope) {
            $parameters['scope'] = $this->_scope;
        }

        $http = new OAuth2_HttpClient($this->_configuration->getAccessTokenEndpoint(), 'POST', http_build_query($parameters));
        $http->setDebug(true);
        $http->execute();
        return $this->_parseAccessTokenResponse($http);
    }

    /**
     * refresh access token
     *
     * @param OAuth2_Token $token
     * @return OAuth2_Token new token object
     */
    public function refreshAccessToken(OAuth2_Token $token) {
        if (!$token->getRefreshToken()) {
            throw new OAuth2_Exception('could not refresh access token, no refresh token available');
        }

        $parameters = array(
            'grant_type' => 'refresh_token',
            'type' => 'web_server',
            'client_id' => $this->_client->getClientKey(),
            'client_secret' => $this->_client->getClientSecret(),
            'refresh_token' => $token->getRefreshToken(),
        );

        $http = new OAuth2_HttpClient($this->_configuration->getAccessTokenEndpoint(), 'POST', http_build_query($parameters));
        $http->execute();

        return $this->_parseAccessTokenResponse($http, $token->getRefreshToken());
    }

    /**
     * parse the response of an access token request and store it in dataStore
     *
     * @param OAuth2_HttpClient $http
     * @param string $oldRefreshToken
     * @return OAuth2_Token
     */
    private function _parseAccessTokenResponse(OAuth2_HttpClient $http, $oldRefreshToken = null) {
        $headers = $http->getHeaders();
        $type = 'text';
        if (isset($headers['Content-Type']) && strpos($headers['Content-Type'], 'application/json') !== false) {
            $type = 'json';
        }

        switch ($type) {
            case 'json':
                $response = json_decode($http->getResponse(), true);
                break;
            case 'text':
            default:
                $response = OAuth2_HttpClient::parseStringToArray($http->getResponse(), '&', '=');
                break;
        }


        if (isset($response['error'])) {
            throw new OAuth2_Exception('got error while requesting access token: ' . $response['error']);
        }
        if (!isset($response['access_token'])) {
            return null;
            // commented out to allow negative case --> provide incorrect authorization token still returns result code 200 OK; probable defect see redmine #16786
            //throw new OAuth2_Exception('no access_token found');
        }

        $token = new OAuth2_Token($response['access_token'], isset($response['refresh_token']) ? $response['refresh_token'] : $oldRefreshToken, isset($response['expires_in']) ? $response['expires_in'] : null);

        unset($response['access_token']);
        unset($response['refresh_token']);
        unset($response['expires_in']);

        // add additional parameters which may be returned depending on service and scope
        foreach ($response as $key => $value) {
            $token->{'set' . $key}($value);
        }

        $this->_dataStore->storeAccessToken($token);

        return $token;
    }

    /**
     * call an api endpoint. automatically adds needed authorization headers with access token or parameters
     *
     * @param string $endpoint
     * @param string $method default 'GET'
     * @param array $uriParameters optional
     * @param mixed $postBody optional, can be string or array
     * @param array $additionalHeaders
     * @return string
     */ public function callApiEndpoint($endpoint, $method = 'GET', array $uriParameters = array(), $postBody = null, array $additionalHeaders = array()) {
        $token = $this->_dataStore->retrieveAccessToken();

        //check if token is invalid
        if ($token->getLifeTime() && $token->getLifeTime() < time()) {
            $token = $this->refreshAccessToken($token);
        }

        $parameters = null;

        $authorizationMethod = $this->_configuration->getAuthorizationMethod();

        switch ($authorizationMethod) {
            case OAuth2_Service_Configuration::AUTHORIZATION_METHOD_HEADER:
                $additionalHeaders = array_merge(array('Authorization: OAuth ' . $token->getAccessToken()), $additionalHeaders);
                break;
            case OAuth2_Service_Configuration::AUTHORIZATION_METHOD_ALTERNATIVE:
                if ($method !== 'GET') {
                    if (is_array($postBody)) {
                        $postBody['oauth_token'] = $token->getAccessToken();
                    } else {
                        $postBody .= '&oauth_token=' . urlencode($token->getAccessToken());
                    }
                } else {
                    $uriParameters['oauth_token'] = $token->getAccessToken();
                }
                break;
            default:
                throw new OAuth2_Exception("Invalid authorization method specified");
                break;
        }

        if ($method !== 'GET') {
            if (is_array($postBody)) {
                $parameters = http_build_query($postBody);
            } else {
                $parameters = $postBody;
            }
        }

        if (!empty($uriParameters)) {
            $endpoint .= (strpos($endpoint, '?') !== false ? '&' : '?') . http_build_query($uriParameters);
        }


        $http = new OAuth2_HttpClient($endpoint, $method, $parameters, $additionalHeaders);
        $http->execute();

        return $http->getResponse();
    }

}

class OAuth2_Token {

    /**
     * @var string
     */
    private $_accessToken;

    /**
     * @var string
     */
    private $_refreshToken;

    /**
     * @var string
     */
    private $_lifeTime;

    /**
     * @var array
     */
    private $_additionalParams = array();

    /**
     *
     * @param string $accessToken
     * @param string $refreshToken
     * @param int $lifeTime
     */
    public function __construct($accessToken = null, $refreshToken = null, $lifeTime = null) {
        $this->_accessToken = $accessToken;
        $this->_refreshToken = $refreshToken;
        if ($lifeTime) {
            $this->_lifeTime = ((int) $lifeTime) + time();
        }
    }

    /**
     * magic method for setting and getting additional parameters returned from
     * service
     *
     * e.g. user_id parameter with scope openid
     *
     * @param string $name
     * @param array $arguments
     * @return mixed
     */
    public function __call($name, $arguments) {
        if (strlen($name) < 4) {
            throw new OAuth2_Exception('undefined magic method called');
        }
        $method = substr($name, 0, 3);
        $param = substr($name, 3);
        switch ($method) {
            case 'get':
                if (!isset($this->_additionalParams[$param])) {
                    throw new OAuth2_Exception($param . ' was not returned by service');
                }
                return $this->_additionalParams[$param];
            case 'set':
                if (!array_key_exists(0, $arguments)) {
                    throw new OAuth2_Exception('magic setter has no argument');
                }
                $this->_additionalParams[$param] = $arguments[0];
                break;
            default:
                throw new OAuth2_Exception('undefined magic method called');
        }
    }

    /**
     * @return string
     */
    public function getAccessToken() {
        return $this->_accessToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken() {
        return $this->_refreshToken;
    }

    /**
     * @return int
     */
    public function getLifeTime() {
        return $this->_lifeTime;
    }

}

class OAuth2_DataStore_Session implements OAuth2_DataStore_Interface {

    public function __construct() {
        session_start();
    }

    public function storeClientSecret($secret) {
        $_SESSION['client_secret'] = $secret;
    }

    public function retrieveClientSecret() {
        return isset($_SESSION['client_secret']) ? $_SESSION['client_secret'] : new OAuth2_Token();
    }

    public function storeClientId($client_id) {
        $_SESSION['client_id'] = $client_id;
    }

    public function retrieveClientId() {
        return isset($_SESSION['client_id']) ? $_SESSION['client_id'] : new OAuth2_Token();
    }

    public function storeBaseUri($base_uri) {
        $_SESSION['base_uri'] = $base_uri;
    }

    public function retrieveBaseUri() {
        return isset($_SESSION['base_uri']) ? $_SESSION['base_uri'] : '';
    }

    /**
     *
     * @return OAuth2_Token
     */
    public function retrieveAccessToken() {
        return isset($_SESSION['oauth2_token']) ? $_SESSION['oauth2_token'] : new OAuth2_Token();
    }

    public function storeAccessToken(OAuth2_Token $token) {
        $_SESSION['oauth2_token'] = $token;
    }

    public function retrieveAuthToken() {
        return isset($_SESSION['auth_token']) ? $_SESSION['auth_token'] : null;
    }

    public function storeAuthToken($code = null) {
        $_SESSION['auth_token'] = $code;
    }

    public function __destruct() {
        session_write_close();
    }

}

interface OAuth2_DataStore_Interface {

    /**
     * @param OAuth2_Token $token
     */
    function storeAccessToken(OAuth2_Token $token);

    /**
     * @return OAuth2_Token
     */
    function retrieveAccessToken();
}

class OAuth2_Client {

    /**
     * @var string
     */
    private $_clientKey;

    /**
     * @var string
     */
    private $_clientSecret;

    /**
     * @var string
     */
    private $_callbackUrl;

    /**
     *
     * @param string $clientKey
     * @param string $clientSecret
     * @param string $callbackUrl
     */
    public function __construct($clientKey, $clientSecret, $callbackUrl) {
        $this->_clientKey = $clientKey;
        $this->_clientSecret = $clientSecret;
        $this->_callbackUrl = $callbackUrl;
    }

    /**
     * @return string
     */
    public function getClientKey() {
        return $this->_clientKey;
    }

    public function setClientKey($newkey) {
        return $this->_clientKey = $newkey;
    }

    /**
     * @return string
     */
    public function getClientSecret() {
        return $this->_clientSecret;
    }

    /**
     * @return string
     */
    public function getCallbackUrl() {
        return $this->_callbackUrl;
    }

}

class OAuth2_HttpClient {

    /**
     * @var string
     */
    private $_url;

    /**
     * @var string
     */
    private $_method;

    /**
     * @var string
     */
    private $_parameters;

    /**
     * @var array
     */
    private $_requestHeader;

    /**
     * @var string
     */
    private $_response;

    /**
     * @var array
     */
    private $_headers;

    /**
     * @var array
     */
    private $_info;

    /**
     * @var boolean
     */
    private $_debug = false;

    /**
     * @param string $url
     * @param string $method
     * @param string $parameters
     * @param array $header  any additional header which should be set
     */
    public function __construct($url, $method, $parameters = null, array $header = array()) {
        $this->_url = $url;
        $this->_method = $method;
        $this->_parameters = $parameters;
        $this->_requestHeader = $header;

        $output = "<h2>HTTP Request</h2>\n<table>\n";
        foreach (array('URL' => $url, 'Method' => $method) as $key => $value) {
            $output.="<tr><td>$key</td><td> $value</td>\n";
        }
        $output.="</table>\n<pre>\n<h3>RequestHeader</h3>\n";
        $output.=print_r($header, true);
        $output.="\n<h3>Parameters</h3>\n";
        $output.=print_r($parameters, true);
        $output.="\n</pre>";
        $_SESSION['result'].=$output;
    }

    /**
     * parses a string with two delimiters to an array
     *
     * example:
     *
     * param1=value1&param2=value2
     *
     * will result with delimiters & and = to
     *
     * array(
     *   'param1' => 'value1',
     *   'param2' => 'value2',
     * )
     *
     * @param string $string
     * @param string $firstDelimiter
     * @param string $secondDelimiter
     * @return array
     */
    public static function parseStringToArray($string, $firstDelimiter, $secondDelimiter) {
        $resultArray = array();
        $parts = explode($firstDelimiter, $string);
        foreach ($parts as $part) {
            $partsPart = explode($secondDelimiter, $part);
            $resultArray[$partsPart[0]] = isset($partsPart[1]) ? trim($partsPart[1]) : '';
        }
        return $resultArray;
    }

    /**
     * executes the curl request
     */
    public function execute() {
        try {
            $ch = curl_init();
            if (FALSE === $ch)
                throw new Exception("Failed to initialize");

            if ($this->_method === 'POST') {
                curl_setopt($ch, CURLOPT_URL, $this->_url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $this->_parameters);
            } else {
                curl_setopt($ch, CURLOPT_URL, $this->_url . ($this->_parameters ? '?' . $this->_parameters : ''));
            }

            curl_setopt($ch, CURLOPT_HEADER, 1);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

            if (!empty($this->_requestHeader)) {
                curl_setopt($ch, CURLOPT_HTTPHEADER, $this->_requestHeader);
            }

            //IMPORTANT//
            //Remove the lower line when going live or testing your certificates
            //This line will make sure that the curl does not verify the SSL certificate
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

            $fullResponse = curl_exec($ch);
            if (FALSE === $fullResponse)
                throw new Exception(curl_error($ch), curl_errno($ch));
            $this->_info = curl_getinfo($ch);

            $this->_response = substr($fullResponse, $this->_info['header_size'], strlen($fullResponse));
            if ($this->_response === false) {
                $this->_response = '';
            }
            $headers = rtrim(substr($fullResponse, 0, $this->_info['header_size']));

            $this->_headers = OAuth2_HttpClient::parseStringToArray($headers, PHP_EOL, ':');
            if ($this->_debug) {

                $output = "<h2>HTTP Result</h2>\n<pre>\n<h3>URL</h3>\n";
                $output.=print_r($this->_url, true);
                $output.="\n<h3>Headers</h3>\n<div id='http_response_headers'>\n";
                $output.=print_r($this->_headers, true);
                $output.="\n</div>\n<h3>Response</h3>\n<div id='http_response'>\n";
                $output.=print_r($this->_response, true);
                $output.="\n</div>\n </pre>\n";

                $_SESSION['result'].=$output;
            }
        } catch (Exception $exc) {
            echo $exc->getTraceAsString();
            echo $exc->getMessage();
            echo $exc->getCode();
        }
        curl_close($ch);
    }

    /**
     * @return string
     */
    public function getResponse() {
        return $this->_response;
    }

    /**
     * @return array
     */
    public function getHeaders() {
        return $this->_headers;
    }

    /**
     * @param boolean $debug
     */
    public function setDebug($debug) {
        $this->_debug = $debug;
    }

}

class OAuth2_Exception extends Exception {

}

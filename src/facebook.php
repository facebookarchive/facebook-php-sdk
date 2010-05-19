<?php

if (!function_exists('curl_init')) {
  throw new Exception('Facebook needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
  throw new Exception('Facebook needs the JSON PHP extension.');
}

/**
 * Thrown when an API call returns an exception.
 *
 * @author Naitik Shah <naitik@facebook.com>
 */
class FacebookApiException extends Exception
{
  /**
   * The result from the API server that represents the exception information.
   */
  protected $result;

  /**
   * Make a new API Exception with the given result.
   *
   * @param Array $result the result from the API server
   */
  public function __construct($result) {
    $this->result = $result;

    $code = isset($result['error_code']) ? $result['error_code'] : 0;
    $msg  = isset($result['error'])
              ? $result['error']['message'] : $result['error_msg'];
    parent::__construct($msg, $code);
  }

  /**
   * Return the associated result object returned by the API server.
   *
   * @returns Array the result from the API server
   */
  public function getResult() {
    return $this->result;
  }

  /**
   * Returns the associated type for the error. This will default to
   * 'Exception' when a type is not available.
   *
   * @return String
   */
  public function getType() {
    return
      isset($this->result['error']) && isset($this->result['error']['type'])
      ? $this->result['error']['type']
      : 'Exception';
  }

  /**
   * To make debugging easier.
   *
   * @returns String the string representation of the error
   */
  public function __toString() {
    $str = $this->getType() . ': ';
    if ($this->code != 0) {
      $str .= $this->code . ': ';
    }
    return $str . $this->message;
  }
}

/**
 * Provides access to the Facebook Platform.
 *
 * @author Naitik Shah <naitik@facebook.com>
 */
class Facebook
{
  /**
   * Version.
   */
  const VERSION = '2.0.3';

  /**
   * Default options for curl.
   */
  public static $CURL_OPTS = array(
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 60,
    CURLOPT_USERAGENT      => 'facebook-php-2.0',
  );

  /**
   * List of query parameters that get automatically dropped when rebuilding
   * the current URL.
   */
  protected static $DROP_QUERY_PARAMS = array(
    'session',
  );

  /**
   * Maps aliases to Facebook domains.
   */
  public static $DOMAIN_MAP = array(
    'api'      => 'https://api.facebook.com/',
    'api_read' => 'https://api-read.facebook.com/',
    'graph'    => 'https://graph.facebook.com/',
    'www'      => 'https://www.facebook.com/',
  );

  /**
   * The Application ID.
   */
  protected $appId;

  /**
   * The Application API Secret.
   */
  protected $apiSecret;

  /**
   * The active user session, if one is available.
   */
  protected $session;

  /**
   * Indicates that we already loaded the session as best as we could.
   */
  protected $sessionLoaded = false;

  /**
   * Indicates if Cookie support should be enabled.
   */
  protected $cookieSupport = false;

  /**
   * Base domain for the Cookie.
   */
  protected $baseDomain = '';

  /**
   * Initialize a Facebook Application.
   *
   * The configuration:
   * - appId: the application ID
   * - secret: the application secret
   * - cookie: (optional) boolean true to enable cookie support
   * - domain: (optional) domain for the cookie
   *
   * @param Array $config the application configuration
   */
  public function __construct($config) {
    $this->setAppId($config['appId']);
    $this->setApiSecret($config['secret']);
    if (isset($config['cookie'])) {
      $this->setCookieSupport($config['cookie']);
    }
    if (isset($config['domain'])) {
      $this->setBaseDomain($config['domain']);
    }
  }

  /**
   * Set the Application ID.
   *
   * @param String $appId the Application ID
   */
  public function setAppId($appId) {
    $this->appId = $appId;
    return $this;
  }

  /**
   * Get the Application ID.
   *
   * @return String the Application ID
   */
  public function getAppId() {
    return $this->appId;
  }

  /**
   * Set the API Secret.
   *
   * @param String $appId the API Secret
   */
  public function setApiSecret($apiSecret) {
    $this->apiSecret = $apiSecret;
    return $this;
  }

  /**
   * Get the API Secret.
   *
   * @return String the API Secret
   */
  public function getApiSecret() {
    return $this->apiSecret;
  }

  /**
   * Set the Cookie Support status.
   *
   * @param Boolean $cookieSupport the Cookie Support status
   */
  public function setCookieSupport($cookieSupport) {
    $this->cookieSupport = $cookieSupport;
    return $this;
  }

  /**
   * Get the Cookie Support status.
   *
   * @return Boolean the Cookie Support status
   */
  public function useCookieSupport() {
    return $this->cookieSupport;
  }

  /**
   * Set the base domain for the Cookie.
   *
   * @param String $domain the base domain
   */
  public function setBaseDomain($domain) {
    $this->baseDomain = $domain;
    return $this;
  }

  /**
   * Get the base domain for the Cookie.
   *
   * @return String the base domain
   */
  public function getBaseDomain() {
    return $this->baseDomain;
  }

  /**
   * Set the Session.
   *
   * @param Array $session the session
   * @param Boolean $write_cookie indicate if a cookie should be written. this
   * value is ignored if cookie support has been disabled.
   */
  public function setSession($session=null, $write_cookie=true) {
    $session = $this->validateSessionObject($session);
    $this->sessionLoaded = true;
    $this->session = $session;
    if ($write_cookie) {
      $this->setCookieFromSession($session);
    }
    return $this;
  }

  /**
   * Get the session object. This will automatically look for a signed session
   * sent via the Cookie or Query Parameters if needed.
   *
   * @return Array the session
   */
  public function getSession() {
    if (!$this->sessionLoaded) {
      $session = null;
      $write_cookie = true;

      // try loading session from $_REQUEST
      if (isset($_REQUEST['session'])) {
        $session = json_decode(
          get_magic_quotes_gpc()
            ? stripslashes($_REQUEST['session'])
            : $_REQUEST['session'],
          true
        );
        $session = $this->validateSessionObject($session);
      }

      // try loading session from cookie if necessary
      if (!$session && $this->useCookieSupport()) {
        $cookieName = $this->getSessionCookieName();
        if (isset($_COOKIE[$cookieName])) {
          $session = array();
          parse_str(trim(
            get_magic_quotes_gpc()
              ? stripslashes($_COOKIE[$cookieName])
              : $_COOKIE[$cookieName],
            '"'
          ), $session);
          $session = $this->validateSessionObject($session);
          // write only if we need to delete a invalid session cookie
          $write_cookie = empty($session);
        }
      }

      $this->setSession($session, $write_cookie);
    }

    return $this->session;
  }

  /**
   * Get the UID from the session.
   *
   * @return String the UID if available
   */
  public function getUser() {
    $session = $this->getSession();
    return $session ? $session['uid'] : null;
  }

  /**
   * Get a Login URL for use with redirects. By default, full page redirect is
   * assumed. If you are using the generated URL with a window.open() call in
   * JavaScript, you can pass in display=popup as part of the $params.
   *
   * The parameters:
   * - next: the url to go to after a successful login
   * - cancel_url: the url to go to after the user cancels
   * - req_perms: comma separated list of requested extended perms
   * - display: can be "page" (default, full page) or "popup"
   *
   * @param Array $params provide custom parameters
   * @return String the URL for the login flow
   */
  public function getLoginUrl($params=array()) {
    $currentUrl = $this->getCurrentUrl();
    return $this->getUrl(
      'www',
      'login.php',
      array_merge(array(
        'api_key'         => $this->getAppId(),
        'cancel_url'      => $currentUrl,
        'display'         => 'page',
        'fbconnect'       => 1,
        'next'            => $currentUrl,
        'return_session'  => 1,
        'session_version' => 3,
        'v'               => '1.0',
      ), $params)
    );
  }

  /**
   * Get a Logout URL suitable for use with redirects.
   *
   * The parameters:
   * - next: the url to go to after a successful logout
   *
   * @param Array $params provide custom parameters
   * @return String the URL for the logout flow
   */
  public function getLogoutUrl($params=array()) {
    $session = $this->getSession();
    return $this->getUrl(
      'www',
      'logout.php',
      array_merge(array(
        'api_key'     => $this->getAppId(),
        'next'        => $this->getCurrentUrl(),
        'session_key' => $session['session_key'],
      ), $params)
    );
  }

  /**
   * Get a login status URL to fetch the status from facebook.
   *
   * The parameters:
   * - ok_session: the URL to go to if a session is found
   * - no_session: the URL to go to if the user is not connected
   * - no_user: the URL to go to if the user is not signed into facebook
   *
   * @param Array $params provide custom parameters
   * @return String the URL for the logout flow
   */
  public function getLoginStatusUrl($params=array()) {
    return $this->getUrl(
      'www',
      'extern/login_status.php',
      array_merge(array(
        'api_key'         => $this->getAppId(),
        'no_session'      => $this->getCurrentUrl(),
        'no_user'         => $this->getCurrentUrl(),
        'ok_session'      => $this->getCurrentUrl(),
        'session_version' => 3,
      ), $params)
    );
  }

  /**
   * Make an API call.
   *
   * @param Array $params the API call parameters
   * @return the decoded response
   */
  public function api(/* polymorphic */) {
    $args = func_get_args();
    if (is_array($args[0])) {
      return $this->_restserver($args[0]);
    } else {
      return call_user_func_array(array($this, '_graph'), $args);
    }
  }

  /**
   * Invoke the old restserver.php endpoint.
   *
   * @param Array $params method call object
   * @return the decoded response object
   * @throws FacebookApiException
   */
  protected function _restserver($params) {
    // generic application level parameters
    $params['api_key'] = $this->getAppId();
    $params['format'] = 'json-strings';

    $result = json_decode($this->_oauthRequest(
      $this->getApiUrl($params['method']),
      $params
    ), true);

    // results are returned, errors are thrown
    if (is_array($result) && isset($result['error_code'])) {
      throw new FacebookApiException($result);
    }
    return $result;
  }

  /**
   * Invoke the Graph API.
   *
   * @param String $path the path (required)
   * @param String $method the http method (default 'GET')
   * @param Array $params the query/post data
   * @return the decoded response object
   * @throws FacebookApiException
   */
  protected function _graph($path, $method='GET', $params=array()) {
    if (is_array($method) && empty($params)) {
      $params = $method;
      $method = 'GET';
    }
    $params['method'] = $method; // method override as we always do a POST

    $result = json_decode($this->_oauthRequest(
      $this->getUrl('graph', $path),
      $params
    ), true);

    // results are returned, errors are thrown
    if (is_array($result) && isset($result['error'])) {
      $e = new FacebookApiException($result);
      if ($e->getType() === 'OAuthException') {
        $this->setSession(null);
      }
      throw $e;
    }
    return $result;
  }

  /**
   * Make a OAuth Request
   *
   * @param String $path the path (required)
   * @param Array $params the query/post data
   * @return the decoded response object
   * @throws FacebookApiException
   */
  protected function _oauthRequest($url, $params) {
    if (!isset($params['access_token'])) {
      $session = $this->getSession();
      // either user session signed, or app signed
      if ($session) {
        $params['access_token'] = $session['access_token'];
      } else {
        $params['access_token'] = $this->getAppId() .'|'. $this->getApiSecret();
      }
    }

    // json_encode all params values that are not strings
    foreach ($params as $key => $value) {
      if (!is_string($value)) {
        $params[$key] = json_encode($value);
      }
    }
    return $this->makeRequest($url, $params);
  }

  /**
   * Makes an HTTP request. This method can be overriden by subclasses if
   * developers want to do fancier things or use something other than curl to
   * make the request.
   *
   * @param String $url the URL to make the request to
   * @param Array $params the parameters to use for the POST body
   * @param CurlHandler $ch optional initialized curl handle
   * @return String the response text
   */
  protected function makeRequest($url, $params, $ch=null) {
    if (!$ch) {
      $ch = curl_init();
    }

    $opts = self::$CURL_OPTS;
    $opts[CURLOPT_POSTFIELDS] = $params;
    $opts[CURLOPT_URL] = $url;
    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);
    if ($result === false) {
      $e = new FacebookApiException(array(
        'error_code' => curl_errno($ch),
        'error'      => array(
          'message' => curl_error($ch),
          'type'    => 'CurlException',
        ),
      ));
      curl_close($ch);
      throw $e;
    }
    curl_close($ch);
    return $result;
  }

  /**
   * The name of the Cookie that contains the session.
   *
   * @return String the cookie name
   */
  protected function getSessionCookieName() {
    return 'fbs_' . $this->getAppId();
  }

  /**
   * Set a JS Cookie based on the _passed in_ session. It does not use the
   * currently stored session -- you need to explicitly pass it in.
   *
   * @param Array $session the session to use for setting the cookie
   */
  protected function setCookieFromSession($session=null) {
    if (!$this->useCookieSupport()) {
      return;
    }

    $cookieName = $this->getSessionCookieName();
    $value = 'deleted';
    $expires = time() - 3600;
    $domain = $this->getBaseDomain();
    if ($session) {
      $value = '"' . http_build_query($session, null, '&') . '"';
      if (isset($session['base_domain'])) {
        $domain = $session['base_domain'];
      }
      $expires = $session['expires'];
    }

    // prepend dot if a domain is found
    if ($domain) {
      $domain = '.' . $domain;
    }

    // if an existing cookie is not set, we dont need to delete it
    if ($value == 'deleted' && empty($_COOKIE[$cookieName])) {
      return;
    }

    if (headers_sent()) {
      // disable error log if we are running in a CLI environment
      // @codeCoverageIgnoreStart
      if (php_sapi_name() != 'cli') {
        error_log('Could not set cookie. Headers already sent.');
      }
      // @codeCoverageIgnoreEnd

    // ignore for code coverage as we will never be able to setcookie in a CLI
    // environment
    // @codeCoverageIgnoreStart
    } else {
      setcookie($cookieName, $value, $expires, '/', $domain);
    }
    // @codeCoverageIgnoreEnd
  }

  /**
   * Validates a session_version=3 style session object.
   *
   * @param Array $session the session object
   * @return Array the session object if it validates, null otherwise
   */
  protected function validateSessionObject($session) {
    // make sure some essential fields exist
    if (is_array($session) &&
        isset($session['uid']) &&
        isset($session['session_key']) &&
        isset($session['secret']) &&
        isset($session['access_token']) &&
        isset($session['sig'])) {
      // validate the signature
      $session_without_sig = $session;
      unset($session_without_sig['sig']);
      $expected_sig = self::generateSignature(
        $session_without_sig,
        $this->getApiSecret()
      );
      if ($session['sig'] != $expected_sig) {
        // disable error log if we are running in a CLI environment
        // @codeCoverageIgnoreStart
        if (php_sapi_name() != 'cli') {
          error_log('Got invalid session signature in cookie.');
        }
        // @codeCoverageIgnoreEnd
        $session = null;
      }
      // check expiry time
    } else {
      $session = null;
    }
    return $session;
  }

  /**
   * Build the URL for api given parameters.
   *
   * @param $method String the method name.
   * @return String the URL for the given parameters
   */
  protected function getApiUrl($method) {
    static $READ_ONLY_CALLS =
      array('admin.getallocation' => 1,
            'admin.getappproperties' => 1,
            'admin.getbannedusers' => 1,
            'admin.getlivestreamvialink' => 1,
            'admin.getmetrics' => 1,
            'admin.getrestrictioninfo' => 1,
            'application.getpublicinfo' => 1,
            'auth.getapppublickey' => 1,
            'auth.getsession' => 1,
            'auth.getsignedpublicsessiondata' => 1,
            'comments.get' => 1,
            'connect.getunconnectedfriendscount' => 1,
            'dashboard.getactivity' => 1,
            'dashboard.getcount' => 1,
            'dashboard.getglobalnews' => 1,
            'dashboard.getnews' => 1,
            'dashboard.multigetcount' => 1,
            'dashboard.multigetnews' => 1,
            'data.getcookies' => 1,
            'events.get' => 1,
            'events.getmembers' => 1,
            'fbml.getcustomtags' => 1,
            'feed.getappfriendstories' => 1,
            'feed.getregisteredtemplatebundlebyid' => 1,
            'feed.getregisteredtemplatebundles' => 1,
            'fql.multiquery' => 1,
            'fql.query' => 1,
            'friends.arefriends' => 1,
            'friends.get' => 1,
            'friends.getappusers' => 1,
            'friends.getlists' => 1,
            'friends.getmutualfriends' => 1,
            'gifts.get' => 1,
            'groups.get' => 1,
            'groups.getmembers' => 1,
            'intl.gettranslations' => 1,
            'links.get' => 1,
            'notes.get' => 1,
            'notifications.get' => 1,
            'pages.getinfo' => 1,
            'pages.isadmin' => 1,
            'pages.isappadded' => 1,
            'pages.isfan' => 1,
            'permissions.checkavailableapiaccess' => 1,
            'permissions.checkgrantedapiaccess' => 1,
            'photos.get' => 1,
            'photos.getalbums' => 1,
            'photos.gettags' => 1,
            'profile.getinfo' => 1,
            'profile.getinfooptions' => 1,
            'stream.get' => 1,
            'stream.getcomments' => 1,
            'stream.getfilters' => 1,
            'users.getinfo' => 1,
            'users.getloggedinuser' => 1,
            'users.getstandardinfo' => 1,
            'users.hasapppermission' => 1,
            'users.isappuser' => 1,
            'users.isverified' => 1,
            'video.getuploadlimits' => 1);
    $name = 'api';
    if (isset($READ_ONLY_CALLS[strtolower($method)])) {
      $name = 'api_read';
    }
    return self::getUrl($name, 'restserver.php');
  }

  /**
   * Build the URL for given domain alias, path and parameters.
   *
   * @param $name String the name of the domain
   * @param $path String optional path (without a leading slash)
   * @param $params Array optional query parameters
   * @return String the URL for the given parameters
   */
  protected function getUrl($name, $path='', $params=array()) {
    $url = self::$DOMAIN_MAP[$name];
    if ($path) {
      if ($path[0] === '/') {
        $path = substr($path, 1);
      }
      $url .= $path;
    }
    if ($params) {
      $url .= '?' . http_build_query($params);
    }
    return $url;
  }

  /**
   * Returns the Current URL, stripping it of known FB parameters that should
   * not persist.
   *
   * @return String the current URL
   */
  protected function getCurrentUrl() {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on'
      ? 'https://'
      : 'http://';
    $currentUrl = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $parts = parse_url($currentUrl);

    // drop known fb params
    $query = '';
    if (!empty($parts['query'])) {
      $params = array();
      parse_str($parts['query'], $params);
      foreach(self::$DROP_QUERY_PARAMS as $key) {
        unset($params[$key]);
      }
      if (!empty($params)) {
        $query = '?' . http_build_query($params);
      }
    }

    // use port if non default
    $port =
      isset($parts['port']) &&
      (($protocol === 'http://' && $parts['port'] !== 80) ||
       ($protocol === 'https://' && $parts['port'] !== 443))
      ? ':' . $parts['port'] : '';

    // rebuild
    return $protocol . $parts['host'] . $port . $parts['path'] . $query;
  }

  /**
   * Generate a signature for the given params and secret.
   *
   * @param Array $params the parameters to sign
   * @param String $secret the secret to sign with
   * @return String the generated signature
   */
  protected static function generateSignature($params, $secret) {
    // work with sorted data
    ksort($params);

    // generate the base string
    $base_string = '';
    foreach($params as $key => $value) {
      $base_string .= $key . '=' . $value;
    }
    $base_string .= $secret;

    return md5($base_string);
  }
}

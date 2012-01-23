<?php
/**
 * Copyright 2011 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

class PHPSDKTestCase extends PHPUnit_Framework_TestCase {
  const APP_ID = '117743971608120';
  const SECRET = '943716006e74d9b9283d4d5d8ab93204';

  const MIGRATED_APP_ID = '174236045938435';
  const MIGRATED_SECRET = '0073dce2d95c4a5c2922d1827ea0cca6';

  private static $kExpiredAccessToken = '206492729383450|2.N4RKywNPuHAey7CK56_wmg__.3600.1304560800.1-214707|6Q14AfpYi_XJB26aRQumouzJiGA';
  private static $kValidSignedRequest = '1sxR88U4SW9m6QnSxwCEw_CObqsllXhnpP5j2pxD97c.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyODEwNTI4MDAsIm9hdXRoX3Rva2VuIjoiMTE3NzQzOTcxNjA4MTIwfDIuVlNUUWpub3hYVVNYd1RzcDB1U2g5d19fLjg2NDAwLjEyODEwNTI4MDAtMTY3Nzg0NjM4NXx4NURORHBtcy1nMUM0dUJHQVYzSVdRX2pYV0kuIiwidXNlcl9pZCI6IjE2Nzc4NDYzODUifQ';
  private static $kNonTosedSignedRequest = 'c0Ih6vYvauDwncv0n0pndr0hP0mvZaJPQDPt6Z43O0k.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiJ9';
  private static $kSignedRequestWithBogusSignature = '1sxR32U4SW9m6QnSxwCEw_CObqsllXhnpP5j2pxD97c.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyODEwNTI4MDAsIm9hdXRoX3Rva2VuIjoiMTE3NzQzOTcxNjA4MTIwfDIuVlNUUWpub3hYVVNYd1RzcDB1U2g5d19fLjg2NDAwLjEyODEwNTI4MDAtMTY3Nzg0NjM4NXx4NURORHBtcy1nMUM0dUJHQVYzSVdRX2pYV0kuIiwidXNlcl9pZCI6IjE2Nzc4NDYzODUifQ';

  public function testConstructor() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $this->assertEquals($facebook->getAppId(), self::APP_ID,
                        'Expect the App ID to be set.');
    $this->assertEquals($facebook->getAppSecret(), self::SECRET,
                        'Expect the API secret to be set.');
  }

  public function testConstructorWithFileUpload() {
    $facebook = new TransientFacebook(array(
      'appId'      => self::APP_ID,
      'secret'     => self::SECRET,
      'fileUpload' => true,
    ));
    $this->assertEquals($facebook->getAppId(), self::APP_ID,
                        'Expect the App ID to be set.');
    $this->assertEquals($facebook->getAppSecret(), self::SECRET,
                        'Expect the API secret to be set.');
    $this->assertTrue($facebook->getFileUploadSupport(),
                      'Expect file upload support to be on.');
    // alias (depricated) for getFileUploadSupport -- test until removed
    $this->assertTrue($facebook->useFileUploadSupport(),
                      'Expect file upload support to be on.');
  }

  public function testSetAppId() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $facebook->setAppId('dummy');
    $this->assertEquals($facebook->getAppId(), 'dummy',
                        'Expect the App ID to be dummy.');
  }

  public function testSetAPISecret() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $facebook->setApiSecret('dummy');
    $this->assertEquals($facebook->getApiSecret(), 'dummy',
                        'Expect the API secret to be dummy.');
  }

  public function testSetAPPSecret() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $facebook->setAppSecret('dummy');
    $this->assertEquals($facebook->getAppSecret(), 'dummy',
                        'Expect the API secret to be dummy.');
  }

  public function testSetAccessToken() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setAccessToken('saltydog');
    $this->assertEquals($facebook->getAccessToken(), 'saltydog',
                        'Expect installed access token to remain \'saltydog\'');
  }

  public function testSetFileUploadSupport() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $this->assertFalse($facebook->getFileUploadSupport(),
                       'Expect file upload support to be off.');
    // alias for getFileUploadSupport (depricated), testing until removed
    $this->assertFalse($facebook->useFileUploadSupport(),
                       'Expect file upload support to be off.');
    $facebook->setFileUploadSupport(true);
    $this->assertTrue($facebook->getFileUploadSupport(),
                      'Expect file upload support to be on.');
    // alias for getFileUploadSupport (depricated), testing until removed
    $this->assertTrue($facebook->useFileUploadSupport(),
                      'Expect file upload support to be on.');
  }

  public function testGetCurrentURL() {
    $facebook = new FBGetCurrentURLFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // fake the HPHP $_SERVER globals
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php?one=one&two=two&three=three';
    $current_url = $facebook->publicGetCurrentUrl();
    $this->assertEquals(
      'http://www.test.com/unit-tests.php?one=one&two=two&three=three',
      $current_url,
      'getCurrentUrl function is changing the current URL');

    // ensure structure of valueless GET params is retained (sometimes
    // an = sign was present, and sometimes it was not)
    // first test when equal signs are present
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php?one=&two=&three=';
    $current_url = $facebook->publicGetCurrentUrl();
    $this->assertEquals(
      'http://www.test.com/unit-tests.php?one=&two=&three=',
      $current_url,
      'getCurrentUrl function is changing the current URL');

    // now confirm that
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php?one&two&three';
    $current_url = $facebook->publicGetCurrentUrl();
    $this->assertEquals(
      'http://www.test.com/unit-tests.php?one&two&three',
      $current_url,
      'getCurrentUrl function is changing the current URL');
  }

  public function testGetLoginURL() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // fake the HPHP $_SERVER globals
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php';
    $login_url = parse_url($facebook->getLoginUrl());
    $this->assertEquals($login_url['scheme'], 'https');
    $this->assertEquals($login_url['host'], 'www.facebook.com');
    $this->assertEquals($login_url['path'], '/dialog/oauth');
    $expected_login_params =
      array('client_id' => self::APP_ID,
            'redirect_uri' => 'http://www.test.com/unit-tests.php');

    $query_map = array();
    parse_str($login_url['query'], $query_map);
    $this->assertIsSubset($expected_login_params, $query_map);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    $this->assertEquals(strlen($query_map['state']), $num_characters = 32);
  }

  public function testGetLoginURLWithExtraParams() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // fake the HPHP $_SERVER globals
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php';
    $extra_params = array('scope' => 'email, sms',
                          'nonsense' => 'nonsense');
    $login_url = parse_url($facebook->getLoginUrl($extra_params));
    $this->assertEquals($login_url['scheme'], 'https');
    $this->assertEquals($login_url['host'], 'www.facebook.com');
    $this->assertEquals($login_url['path'], '/dialog/oauth');
    $expected_login_params =
      array_merge(
        array('client_id' => self::APP_ID,
              'redirect_uri' => 'http://www.test.com/unit-tests.php'),
        $extra_params);
    $query_map = array();
    parse_str($login_url['query'], $query_map);
    $this->assertIsSubset($expected_login_params, $query_map);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    $this->assertEquals(strlen($query_map['state']), $num_characters = 32);
  }

  public function testGetLoginURLWithScopeParamsAsArray() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // fake the HPHP $_SERVER globals
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php';
    $scope_params_as_array = array('email','sms','read_stream');
    $extra_params = array('scope' => $scope_params_as_array,
                          'nonsense' => 'nonsense');
    $login_url = parse_url($facebook->getLoginUrl($extra_params));
    $this->assertEquals($login_url['scheme'], 'https');
    $this->assertEquals($login_url['host'], 'www.facebook.com');
    $this->assertEquals($login_url['path'], '/dialog/oauth');
    // expect api to flatten array params to comma separated list
    // should do the same here before asserting to make sure API is behaving
    // correctly;
    $extra_params['scope'] = implode(',', $scope_params_as_array);
    $expected_login_params =
      array_merge(
        array('client_id' => self::APP_ID,
              'redirect_uri' => 'http://www.test.com/unit-tests.php'),
        $extra_params);
    $query_map = array();
    parse_str($login_url['query'], $query_map);
    $this->assertIsSubset($expected_login_params, $query_map);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    $this->assertEquals(strlen($query_map['state']), $num_characters = 32);
  }

  public function testGetCodeWithValidCSRFState() {
    $facebook = new FBCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setCSRFStateToken();
    $code = $_REQUEST['code'] = $this->generateMD5HashOfRandomValue();
    $_REQUEST['state'] = $facebook->getCSRFStateToken();
    $this->assertEquals($code,
                        $facebook->publicGetCode(),
                        'Expect code to be pulled from $_REQUEST[\'code\']');
  }

  public function testGetCodeWithInvalidCSRFState() {
    $facebook = new FBCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setCSRFStateToken();
    $code = $_REQUEST['code'] = $this->generateMD5HashOfRandomValue();
    $_REQUEST['state'] = $facebook->getCSRFStateToken().'forgery!!!';
    $this->assertFalse($facebook->publicGetCode(),
                       'Expect getCode to fail, CSRF state should not match.');
  }

  public function testGetCodeWithMissingCSRFState() {
    $facebook = new FBCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $code = $_REQUEST['code'] = $this->generateMD5HashOfRandomValue();
    // intentionally don't set CSRF token at all
    $this->assertFalse($facebook->publicGetCode(),
                       'Expect getCode to fail, CSRF state not sent back.');

  }

  public function testGetUserFromSignedRequest() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $_REQUEST['signed_request'] = self::$kValidSignedRequest;
    $this->assertEquals('1677846385', $facebook->getUser(),
                        'Failed to get user ID from a valid signed request.');
  }

  public function testGetSignedRequestFromCookie() {
    $facebook = new FBGetSignedRequestCookieFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $_COOKIE[$facebook->publicGetSignedRequestCookieName()] =
      self::$kValidSignedRequest;
    $this->assertNotNull($facebook->publicGetSignedRequest());
    $this->assertEquals('1677846385', $facebook->getUser(),
                        'Failed to get user ID from a valid signed request.');
  }

  public function testGetSignedRequestWithIncorrectSignature() {
    $facebook = new FBGetSignedRequestCookieFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $_COOKIE[$facebook->publicGetSignedRequestCookieName()] =
      self::$kSignedRequestWithBogusSignature;
    $this->assertNull($facebook->publicGetSignedRequest());
  }

  public function testNonUserAccessToken() {
    $facebook = new FBAccessToken(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // no cookies, and no request params, so no user or code,
    // so no user access token (even with cookie support)
    $this->assertEquals($facebook->publicGetApplicationAccessToken(),
                        $facebook->getAccessToken(),
                        'Access token should be that for logged out users.');
  }

  public function testAPIForLoggedOutUsers() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $response = $facebook->api(array(
      'method' => 'fql.query',
      'query' => 'SELECT name FROM user WHERE uid=4',
    ));
    $this->assertEquals(count($response), 1,
                        'Expect one row back.');
    $this->assertEquals($response[0]['name'], 'Mark Zuckerberg',
                        'Expect the name back.');
  }

  public function testAPIWithBogusAccessToken() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setAccessToken('this-is-not-really-an-access-token');
    // if we don't set an access token and there's no way to
    // get one, then the FQL query below works beautifully, handing
    // over Zuck's public data.  But if you specify a bogus access
    // token as I have right here, then the FQL query should fail.
    // We could return just Zuck's public data, but that wouldn't
    // advertise the issue that the access token is at worst broken
    // and at best expired.
    try {
      $response = $facebook->api(array(
        'method' => 'fql.query',
        'query' => 'SELECT name FROM profile WHERE id=4',
      ));
      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      $result = $e->getResult();
      $this->assertTrue(is_array($result), 'expect a result object');
      $this->assertEquals('190', $result['error_code'], 'expect code');
    }
  }

  public function testAPIGraphPublicData() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $response = $facebook->api('/jerry');
    $this->assertEquals(
      $response['id'], '214707', 'should get expected id.');
  }

  public function testGraphAPIWithBogusAccessToken() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setAccessToken('this-is-not-really-an-access-token');
    try {
      $response = $facebook->api('/me');
      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      // means the server got the access token and didn't like it
      $msg = 'OAuthException: Invalid OAuth access token.';
      $this->assertEquals($msg, (string) $e,
                          'Expect the invalid OAuth token message.');
    }
  }

  public function testGraphAPIWithExpiredAccessToken() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setAccessToken(self::$kExpiredAccessToken);
    try {
      $response = $facebook->api('/me');
      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      // means the server got the access token and didn't like it
      $error_msg_start = 'OAuthException: Error validating access token:';
      $this->assertTrue(strpos((string) $e, $error_msg_start) === 0,
                        'Expect the token validation error message.');
    }
  }

  public function testGraphAPIMethod() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    try {
      // naitik being bold about deleting his entire record....
      // let's hope this never actually passes.
      $response = $facebook->api('/naitik', $method = 'DELETE');
      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      // ProfileDelete means the server understood the DELETE
      $msg =
        'OAuthException: (#200) User cannot access this application';
      $this->assertEquals($msg, (string) $e,
                          'Expect the invalid session message.');
    }
  }

  public function testGraphAPIOAuthSpecError() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::MIGRATED_APP_ID,
      'secret' => self::MIGRATED_SECRET,
    ));

    try {
      $response = $facebook->api('/me', array(
        'client_id' => self::MIGRATED_APP_ID));

      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      // means the server got the access token
      $msg = 'invalid_request: An active access token must be used '.
             'to query information about the current user.';
      $this->assertEquals($msg, (string) $e,
                          'Expect the invalid session message.');
    }
  }

  public function testGraphAPIMethodOAuthSpecError() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::MIGRATED_APP_ID,
      'secret' => self::MIGRATED_SECRET,
    ));

    try {
      $response = $facebook->api('/daaku.shah', 'DELETE', array(
        'client_id' => self::MIGRATED_APP_ID));
      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      $this->assertEquals(strpos($e, 'invalid_request'), 0);
    }
  }

  public function testCurlFailure() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    if (!defined('CURLOPT_TIMEOUT_MS')) {
      // can't test it if we don't have millisecond timeouts
      return;
    }

    $exception = null;
    try {
      // we dont expect facebook will ever return in 1ms
      Facebook::$CURL_OPTS[CURLOPT_TIMEOUT_MS] = 50;
      $facebook->api('/naitik');
    } catch(FacebookApiException $e) {
      $exception = $e;
    }
    unset(Facebook::$CURL_OPTS[CURLOPT_TIMEOUT_MS]);
    if (!$exception) {
      $this->fail('no exception was thrown on timeout.');
    }

    $this->assertEquals(
      CURLE_OPERATION_TIMEOUTED, $exception->getCode(), 'expect timeout');
    $this->assertEquals('CurlException', $exception->getType(), 'expect type');
  }

  public function testGraphAPIWithOnlyParams() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $response = $facebook->api('/jerry');
    $this->assertTrue(isset($response['id']),
                      'User ID should be public.');
    $this->assertTrue(isset($response['name']),
                      'User\'s name should be public.');
    $this->assertTrue(isset($response['first_name']),
                      'User\'s first name should be public.');
    $this->assertTrue(isset($response['last_name']),
                      'User\'s last name should be public.');
    $this->assertFalse(isset($response['work']),
                       'User\'s work history should only be available with '.
                       'a valid access token.');
    $this->assertFalse(isset($response['education']),
                       'User\'s education history should only be '.
                       'available with a valid access token.');
    $this->assertFalse(isset($response['verified']),
                       'User\'s verification status should only be '.
                       'available with a valid access token.');
  }

  public function testLoginURLDefaults() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertNotNull(strpos($facebook->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testLoginURLDefaultsDropStateQueryParam() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples?state=xx42xx';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertTrue(strpos($facebook->getLoginUrl(), $expectEncodedUrl) > -1,
                      'Expect the current url to exist.');
    $this->assertFalse(strpos($facebook->getLoginUrl(), 'xx42xx'),
                       'Expect the session param to be dropped.');
  }

  public function testLoginURLDefaultsDropCodeQueryParam() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples?code=xx42xx';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertTrue(strpos($facebook->getLoginUrl(), $expectEncodedUrl) > -1,
                      'Expect the current url to exist.');
    $this->assertFalse(strpos($facebook->getLoginUrl(), 'xx42xx'),
                       'Expect the session param to be dropped.');
  }

  public function testLoginURLDefaultsDropSignedRequestParamButNotOthers() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] =
      '/examples?signed_request=xx42xx&do_not_drop=xx43xx';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertFalse(strpos($facebook->getLoginUrl(), 'xx42xx'),
                       'Expect the session param to be dropped.');
    $this->assertTrue(strpos($facebook->getLoginUrl(), 'xx43xx') > -1,
                      'Expect the do_not_drop param to exist.');
  }

  public function testLoginURLCustomNext() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $next = 'http://fbrell.com/custom';
    $loginUrl = $facebook->getLoginUrl(array(
      'redirect_uri' => $next,
      'cancel_url' => $next
    ));
    $currentEncodedUrl = rawurlencode('http://fbrell.com/examples');
    $expectedEncodedUrl = rawurlencode($next);
    $this->assertNotNull(strpos($loginUrl, $expectedEncodedUrl),
                         'Expect the custom url to exist.');
    $this->assertFalse(strpos($loginUrl, $currentEncodedUrl),
                      'Expect the current url to not exist.');
  }

  public function testLogoutURLDefaults() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertNotNull(strpos($facebook->getLogoutUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testLoginStatusURLDefaults() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertNotNull(strpos($facebook->getLoginStatusUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testLoginStatusURLCustom() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl1 = rawurlencode('http://fbrell.com/examples');
    $okUrl = 'http://fbrell.com/here1';
    $encodedUrl2 = rawurlencode($okUrl);
    $loginStatusUrl = $facebook->getLoginStatusUrl(array(
      'ok_session' => $okUrl,
    ));
    $this->assertNotNull(strpos($loginStatusUrl, $encodedUrl1),
                         'Expect the current url to exist.');
    $this->assertNotNull(strpos($loginStatusUrl, $encodedUrl2),
                         'Expect the custom url to exist.');
  }

  public function testNonDefaultPort() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com:8080';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com:8080/examples');
    $this->assertNotNull(strpos($facebook->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testSecureCurrentUrl() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $_SERVER['HTTPS'] = 'on';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('https://fbrell.com/examples');
    $this->assertNotNull(strpos($facebook->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testSecureCurrentUrlWithNonDefaultPort() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com:8080';
    $_SERVER['REQUEST_URI'] = '/examples';
    $_SERVER['HTTPS'] = 'on';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('https://fbrell.com:8080/examples');
    $this->assertNotNull(strpos($facebook->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testAppSecretCall() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    try {
      $response = $facebook->api('/' . self::APP_ID . '/insights');
      $this->fail('Desktop applications need a user token for insights.');
    } catch (FacebookApiException $e) {
      // this test is failing as the graph call is returning the wrong
      // error message
      $this->assertTrue(strpos($e->getMessage(),
        'Requires session when calling from a desktop app') !== false,
        'Incorrect exception type thrown when trying to gain ' .
        'insights for desktop app without a user access token.');
    } catch (Exception $e) {
      $this->fail('Incorrect exception type thrown when trying to gain ' .
        'insights for desktop app without a user access token.');
    }
  }

  public function testBase64UrlEncode() {
    $input = 'Facebook rocks';
    $output = 'RmFjZWJvb2sgcm9ja3M';

    $this->assertEquals(FBPublic::publicBase64UrlDecode($output), $input);
  }

  public function testSignedToken() {
    $facebook = new FBPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));
    $payload = $facebook->publicParseSignedRequest(self::$kValidSignedRequest);
    $this->assertNotNull($payload, 'Expected token to parse');
    $this->assertEquals($facebook->getSignedRequest(), null);
    $_REQUEST['signed_request'] = self::$kValidSignedRequest;
    $this->assertEquals($facebook->getSignedRequest(), $payload);
  }

  public function testNonTossedSignedtoken() {
    $facebook = new FBPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));
    $payload = $facebook->publicParseSignedRequest(
      self::$kNonTosedSignedRequest);
    $this->assertNotNull($payload, 'Expected token to parse');
    $this->assertNull($facebook->getSignedRequest());
    $_REQUEST['signed_request'] = self::$kNonTosedSignedRequest;
    $this->assertEquals($facebook->getSignedRequest(),
      array('algorithm' => 'HMAC-SHA256'));
  }

  public function testBundledCACert() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));

      // use the bundled cert from the start
    Facebook::$CURL_OPTS[CURLOPT_CAINFO] =
      dirname(__FILE__) . '/../src/fb_ca_chain_bundle.crt';
    $response = $facebook->api('/naitik');

    unset(Facebook::$CURL_OPTS[CURLOPT_CAINFO]);
    $this->assertEquals(
      $response['id'], '5526183', 'should get expected id.');
  }

  public function testVideoUpload() {
    $facebook = new FBRecordURL(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));

    $facebook->api(array('method' => 'video.upload'));
    $this->assertContains('//api-video.', $facebook->getRequestedURL(),
                          'video.upload should go against api-video');
  }

  public function testGetUserAndAccessTokenFromSession() {
    $facebook = new PersistentFBPublic(array(
                                         'appId'  => self::APP_ID,
                                         'secret' => self::SECRET
                                       ));

    $facebook->publicSetPersistentData('access_token',
                                       self::$kExpiredAccessToken);
    $facebook->publicSetPersistentData('user_id', 12345);
    $this->assertEquals(self::$kExpiredAccessToken,
                        $facebook->getAccessToken(),
                        'Get access token from persistent store.');
    $this->assertEquals('12345',
                        $facebook->getUser(),
                        'Get user id from persistent store.');
  }

  public function testGetUserAndAccessTokenFromSignedRequestNotSession() {
    $facebook = new PersistentFBPublic(array(
                                         'appId'  => self::APP_ID,
                                         'secret' => self::SECRET
                                       ));

    $_REQUEST['signed_request'] = self::$kValidSignedRequest;
    $facebook->publicSetPersistentData('user_id', 41572);
    $facebook->publicSetPersistentData('access_token',
                                       self::$kExpiredAccessToken);
    $this->assertNotEquals('41572', $facebook->getUser(),
                           'Got user from session instead of signed request.');
    $this->assertEquals('1677846385', $facebook->getUser(),
                        'Failed to get correct user ID from signed request.');
    $this->assertNotEquals(
      self::$kExpiredAccessToken,
      $facebook->getAccessToken(),
      'Got access token from session instead of signed request.');
    $this->assertNotEmpty(
      $facebook->getAccessToken(),
      'Failed to extract an access token from the signed request.');
  }

  public function testGetUserWithoutCodeOrSignedRequestOrSession() {
    $facebook = new PersistentFBPublic(array(
                                         'appId'  => self::APP_ID,
                                         'secret' => self::SECRET
                                       ));

    // deliberately leave $_REQUEST and _$SESSION empty
    $this->assertEmpty($_REQUEST,
                       'GET, POST, and COOKIE params exist even though '.
                       'they should.  Test cannot succeed unless all of '.
                       '$_REQUEST is empty.');
    $this->assertEmpty($_SESSION,
                       'Session is carrying state and should not be.');
    $this->assertEmpty($facebook->getUser(),
                       'Got a user id, even without a signed request, '.
                       'access token, or session variable.');
    $this->assertEmpty($_SESSION,
                       'Session superglobal incorrectly populated by getUser.');
  }

  protected function generateMD5HashOfRandomValue() {
    return md5(uniqid(mt_rand(), true));
  }

  protected function setUp() {
    parent::setUp();
  }

  protected function tearDown() {
    $this->clearSuperGlobals();
    parent::tearDown();
  }

  protected function clearSuperGlobals() {
    unset($_SERVER['HTTPS']);
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
    $_SESSION = array();
    $_COOKIE = array();
    $_REQUEST = array();
    $_POST = array();
    $_GET = array();
    if (session_id()) {
      session_destroy();
    }
  }

  /**
   * Checks that the correct args are a subset of the returned obj
   * @param  array $correct The correct array values
   * @param  array $actual  The values in practice
   * @param  string $message to be shown on failure
   */
  protected function assertIsSubset($correct, $actual, $msg='') {
    foreach ($correct as $key => $value) {
      $actual_value = $actual[$key];
      $newMsg = (strlen($msg) ? ($msg.' ') : '').'Key: '.$key;
      $this->assertEquals($value, $actual_value, $newMsg);
    }
  }
}

class TransientFacebook extends BaseFacebook {
  protected function setPersistentData($key, $value) {}
  protected function getPersistentData($key, $default = false) {
    return $default;
  }
  protected function clearPersistentData($key) {}
  protected function clearAllPersistentData() {}
}

class FBRecordURL extends TransientFacebook {
  private $url;

  protected function _oauthRequest($url, $params) {
    $this->url = $url;
  }

  public function getRequestedURL() {
    return $this->url;
  }
}

class FBPublic extends TransientFacebook {
  public static function publicBase64UrlDecode($input) {
    return self::base64UrlDecode($input);
  }
  public function publicParseSignedRequest($input) {
    return $this->parseSignedRequest($input);
  }
}

class PersistentFBPublic extends Facebook {
  public function publicParseSignedRequest($input) {
    return $this->parseSignedRequest($input);
  }

  public function publicSetPersistentData($key, $value) {
    $this->setPersistentData($key, $value);
  }
}

class FBCode extends Facebook {
  public function publicGetCode() {
    return $this->getCode();
  }

  public function setCSRFStateToken() {
    $this->establishCSRFTokenState();
  }

  public function getCSRFStateToken() {
    return $this->getPersistentData('state');
  }
}

class FBAccessToken extends TransientFacebook {
  public function publicGetApplicationAccessToken() {
    return $this->getApplicationAccessToken();
  }
}

class FBGetCurrentURLFacebook extends TransientFacebook {
  public function publicGetCurrentUrl() {
    return $this->getCurrentUrl();
  }
}

class FBGetSignedRequestCookieFacebook extends TransientFacebook {
  public function publicGetSignedRequest() {
    return $this->getSignedRequest();
  }

  public function publicGetSignedRequestCookieName() {
    return $this->getSignedRequestCookieName();
  }
}

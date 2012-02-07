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
    self::assertEquals(self::APP_ID, $facebook->getAppId(),
                       'Expect the App ID to be set.');
    self::assertEquals(self::SECRET, $facebook->getAppSecret(),
                       'Expect the API secret to be set.');
  }

  public function testConstructorWithFileUpload() {
    $facebook = new TransientFacebook(array(
      'appId'      => self::APP_ID,
      'secret'     => self::SECRET,
      'fileUpload' => true,
    ));

    self::assertEquals(self::APP_ID, $facebook->getAppId(),
                       'Expect the App ID to be set.');
    self::assertEquals(self::SECRET, $facebook->getAppSecret(),
                       'Expect the API secret to be set.');
    self::assertTrue($facebook->getFileUploadSupport(),
                     'Expect file upload support to be on.');
    // alias (depricated) for getFileUploadSupport -- test until removed
    self::assertTrue($facebook->useFileUploadSupport(),
                     'Expect file upload support to be on.');
  }

  public function testSetAppId() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setAppId('dummy');
    self::assertEquals('dummy', $facebook->getAppId(),
                       'Expect the App ID to be dummy.');
  }

  public function testSetApiSecret() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setApiSecret('dummy');
    self::assertEquals('dummy', $facebook->getApiSecret(),
                       'Expect the API secret to be dummy.');
  }

  public function testSetAppSecret() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setAppSecret('dummy');
    self::assertEquals('dummy', $facebook->getAppSecret(),
                       'Expect the API secret to be dummy.');
  }

  public function testSetAccessToken() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setAccessToken('saltydog');
    self::assertEquals('saltydog', $facebook->getAccessToken(),
                       'Expect installed access token to remain \'saltydog\'');
  }

  public function testSetFileUploadSupport() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    self::assertFalse($facebook->getFileUploadSupport(),
                      'Expect file upload support to start off.');
    // alias for getFileUploadSupport (depricated), testing until removed
    self::assertFalse($facebook->useFileUploadSupport(),
                      'Expect file upload support to start off.');
    $facebook->setFileUploadSupport(true);
    self::assertTrue($facebook->getFileUploadSupport(),
                     'Expect file upload support to be on.');
    // alias for getFileUploadSupport (depricated), testing until removed
    self::assertTrue($facebook->useFileUploadSupport(),
                     'Expect file upload support to be on.');
  }

  public function testGetCurrentUrl() {
    $facebook = new FBGetCurrentUrl(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // fake the PHP $_SERVER globals
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php?one=one&two=two&three=three';
    $current_url = $facebook->publicGetCurrentUrl();
    self::assertEquals(
      'http://www.test.com/unit-tests.php?one=one&two=two&three=three',
      $current_url,
      'getCurrentUrl function is changing the current URL');

    // ensure structure of valueless GET params is retained (sometimes
    // an = sign was present, and sometimes it was not)
    // first test when equal signs are present
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php?one=&two=&three=';
    $current_url = $facebook->publicGetCurrentUrl();
    self::assertEquals(
      'http://www.test.com/unit-tests.php?one=&two=&three=',
      $current_url,
      'getCurrentUrl function is changing the current URL');

    // now confirm that
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php?one&two&three';
    $current_url = $facebook->publicGetCurrentUrl();
    self::assertEquals(
      'http://www.test.com/unit-tests.php?one&two&three',
      $current_url,
      'getCurrentUrl function is changing the current URL');
  }

  public function testGetLoginUrl() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // fake the HPHP $_SERVER globals
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php';
    $login_url = parse_url($facebook->getLoginUrl());
    self::assertEquals($login_url['scheme'], 'https');
    self::assertEquals($login_url['host'], 'www.facebook.com');
    self::assertEquals($login_url['path'], '/dialog/oauth');
    $expected_login_params =
      array('client_id' => self::APP_ID,
            'redirect_uri' => 'http://www.test.com/unit-tests.php');

    $query_map = array();
    parse_str($login_url['query'], $query_map);
    self::assertIsSubset($expected_login_params, $query_map);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    self::assertEquals($num_characters = 32, strlen($query_map['state']));
  }

  public function testGetLoginUrlWithExtraParams() {
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
    self::assertEquals($login_url['scheme'], 'https');
    self::assertEquals($login_url['host'], 'www.facebook.com');
    self::assertEquals($login_url['path'], '/dialog/oauth');
    $expected_login_params =
      array_merge(
        array('client_id' => self::APP_ID,
              'redirect_uri' => 'http://www.test.com/unit-tests.php'),
        $extra_params);
    $query_map = array();
    parse_str($login_url['query'], $query_map);
    self::assertIsSubset($expected_login_params, $query_map);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    self::assertEquals($num_characters = 32, strlen($query_map['state']));
  }

  public function testGetLoginUrlWithScopeParamsAsArray() {
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
    self::assertEquals($login_url['scheme'], 'https');
    self::assertEquals($login_url['host'], 'www.facebook.com');
    self::assertEquals($login_url['path'], '/dialog/oauth');
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
    self::assertIsSubset($expected_login_params, $query_map);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    self::assertEquals($num_characters = 32, strlen($query_map['state']));
  }

  public function testGetCodeWithValidCSRFState() {
    $facebook = new FBCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setCSRFStateToken();
    $code = $_REQUEST['code'] = self::generateMD5HashOfRandomValue();
    $_REQUEST['state'] = $facebook->getCSRFStateToken();
    self::assertEquals($code,
                       $facebook->publicGetCode(),
                       'Expect code to be pulled from $_REQUEST[\'code\']');
  }

  public function testGetCodeWithInvalidCSRFState() {
    $facebook = new FBCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setCSRFStateToken();
    $code = $_REQUEST['code'] = self::generateMD5HashOfRandomValue();
    $_REQUEST['state'] = $facebook->getCSRFStateToken().'forgery!!!';
    self::assertFalse($facebook->publicGetCode(),
                      'Expect getCode to fail, CSRF state should not match.');
  }

  public function testGetCodeWithMissingCSRFState() {
    $facebook = new FBCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $code = $_REQUEST['code'] = self::generateMD5HashOfRandomValue();
    // intentionally don't set CSRF token at all
    self::assertFalse($facebook->publicGetCode(),
                      'Expect getCode to fail, CSRF state not sent back.');

  }

  public function testGetUserFromSignedRequest() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $_REQUEST['signed_request'] = self::$kValidSignedRequest;
    self::assertEquals('1677846385', $facebook->getUser(),
                       'Failed to get user ID from a valid signed request.');
  }

  public function testGetSignedRequestFromCookie() {
    $facebook = new FBGetSignedRequestCookie(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $_COOKIE[$facebook->publicGetSignedRequestCookieName()] =
      self::$kValidSignedRequest;
    self::assertNotNull($facebook->publicGetSignedRequest());
    self::assertEquals('1677846385', $facebook->getUser(),
                       'Failed to get user ID from a valid signed request.');
  }

  public function testGetSignedRequestWithIncorrectSignature() {
    $facebook = new FBGetSignedRequestCookie(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $_COOKIE[$facebook->publicGetSignedRequestCookieName()] =
      self::$kSignedRequestWithBogusSignature;
    self::assertNull($facebook->publicGetSignedRequest());
  }

  public function testNonUserAccessToken() {
    $facebook = new FBAccessToken(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // no cookies, and no request params, so no user or code,
    // so no user access token (even with cookie support)
    self::assertEquals($facebook->publicGetApplicationAccessToken(),
                       $facebook->getAccessToken(),
                       'Access token should be that for logged out users.');
  }

  public function testGraphApiWithBogusAccessToken() {
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
      self::fail('Should not get here.');
    } catch(FacebookApiException $e) {
      self::assertContains('Invalid OAuth access token.',
                           $e->getMessage(),
                           'Expect the invalid OAuth token message.');
      $result = $e->getResult();
      self::assertInternalType('array', $result, 'Expect a result array.');
      self::assertEquals('190', $result['error_code'], 'Expect code.');
    }
  }

  /**
   * @expectedException FacebookApiException
   * @expectedExceptionMessage Session has expired at unix time 1304560800
   */
  public function testGraphApiWithExpiredAccessToken() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $facebook->setAccessToken(self::$kExpiredAccessToken);
    $response = $facebook->api('/me');
  }

  public function testGraphApiWithLoggedOutUser() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $response = $facebook->api(array(
      'method' => 'fql.query',
      'query' => 'SELECT name FROM user WHERE uid=4',
    ));
    self::assertInternalType('array', $response, 'Expect a response array.');
    self::assertCount(1, $response,
                      'Expect one row back.');
    self::assertEquals($response[0]['name'], 'Mark Zuckerberg',
                       'Expect the name back.');
  }

  public function testGraphApiPublicData() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $response = $facebook->api('/jerry');
    self::assertInternalType('array', $response, 'Expect a response array.');
    self::assertEquals(
      '214707', $response['id'], 'Expect id.');
  }

  /**
   * @expectedException FacebookApiException
   * @expectedExceptionMessage User cannot access this application
   */
  public function testGraphApiMethod() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // naitik being bold about deleting his entire record....
    // let's hope this never actually passes.
    $response = $facebook->api('/naitik', $method = 'DELETE');
  }

  /**
   * @expectedException FacebookApiException
   * @expectedExceptionMessage An active access token must be used
   */
  public function testGraphApiWithOAuthSpecError() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::MIGRATED_APP_ID,
      'secret' => self::MIGRATED_SECRET,
    ));

    $response = $facebook->api('/me', array(
      'client_id' => self::MIGRATED_APP_ID));
  }

  /**
   * @expectedException FacebookApiException
   * @expectedExceptionMessage invalid_request
   */
  public function testGraphApiMethodWithOAuthSpecError() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::MIGRATED_APP_ID,
      'secret' => self::MIGRATED_SECRET,
    ));

    $response = $facebook->api('/daaku.shah', 'DELETE', array(
      'client_id' => self::MIGRATED_APP_ID));
  }

  public function testCurlFailure() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    if (!defined('CURLOPT_TIMEOUT_MS')) {
      self::markTestSkipped('Cannot test timeout without millisecond timeouts');
    }

    $exception = null;
    try {
      // we dont expect facebook will ever return in 1ms
      Facebook::$CURL_OPTS[CURLOPT_TIMEOUT_MS] = 50;
      $facebook->api('/naitik');
    } catch(Exception $e) {
      $exception = $e;
    }
    unset(Facebook::$CURL_OPTS[CURLOPT_TIMEOUT_MS]);
    if (!$exception) {
      self::fail('No exception was thrown on timeout.');
    }

    self::assertInstanceOf('FacebookApiException', $exception,
                           'Expect exception type.');
    self::assertEquals(
      CURLE_OPERATION_TIMEOUTED, $exception->getCode(), 'Expect code.');
    self::assertEquals('CurlException', $exception->getType(), 'Expect type.');
  }

  public function testGraphApiWithOnlyParams() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $response = $facebook->api('/jerry');
    self::assertArrayHasKey('id', $response,
                            'User ID should be public.');
    self::assertArrayHasKey('name', $response,
                            'User\'s name should be public.');
    self::assertArrayHasKey('first_name', $response,
                            'User\'s first name should be public.');
    self::assertArrayHasKey('last_name', $response,
                            'User\'s last name should be public.');
    self::assertArrayNotHasKey('work', $response,
                               'User\'s work history should only be available '.
                               'with a valid access token.');
    self::assertArrayNotHasKey('education', $response,
                               'User\'s education history should only be '.
                               'available with a valid access token.');
    self::assertArrayNotHasKey('verified', $response,
                               'User\'s verification status should only be '.
                               'available with a valid access token.');
  }

  public function testLoginUrlDefaults() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    self::assertContains($encodedUrl, $facebook->getLoginUrl(),
                         'Expect the current url to exist.');
  }

  public function testLoginUrlDefaultsDropStateQueryParam() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples?state=xx42xx';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    self::assertContains($encodedUrl, $facebook->getLoginUrl(),
                         'Expect the current url to exist.');
    self::assertNotContains('xx42xx', $facebook->getLoginUrl(),
                            'Expect the session param to be dropped.');
  }

  public function testLoginUrlDefaultsDropCodeQueryParam() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples?code=xx42xx';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    self::assertContains($encodedUrl, $facebook->getLoginUrl(),
                         'Expect the current url to exist.');
    self::assertNotContains('xx42xx', $facebook->getLoginUrl(),
                            'Expect the session param to be dropped.');
  }

  public function testLoginUrlDefaultsDropSignedRequestParamButNotOthers() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] =
      '/examples?signed_request=xx42xx&do_not_drop=xx43xx';
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    self::assertContains($encodedUrl, $facebook->getLoginUrl(),
                         'Expect the current url to exist.');
    self::assertNotContains('xx42xx', $facebook->getLoginUrl(),
                            'Expect the session param to be dropped.');
    self::assertContains('xx43xx', $facebook->getLoginUrl(),
                         'Expect the do_not_drop param to exist.');
  }

  public function testLoginUrlCustomNext() {
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
    self::assertContains($expectedEncodedUrl, $loginUrl,
                         'Expect the custom url to exist.');
    self::assertNotContains($currentEncodedUrl, $loginUrl,
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
    self::assertContains($encodedUrl, $facebook->getLogoutUrl(),
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
    self::assertContains($encodedUrl, $facebook->getLoginStatusUrl(),
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
    self::assertContains($encodedUrl1, $loginStatusUrl,
                         'Expect the current url to exist.');
    self::assertContains($encodedUrl2, $loginStatusUrl,
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
    self::assertContains($encodedUrl, $facebook->getLoginUrl(),
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
    self::assertContains($encodedUrl, $facebook->getLoginUrl(),
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
    self::assertContains($encodedUrl, $facebook->getLoginUrl(),
                         'Expect the current url to exist.');
  }

  /**
   * @expectedException FacebookApiException
   * @expectedExceptionMessage Requires session when calling from a desktop app
   */
  public function testAppSecretCall() {
    $facebook = new TransientFacebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $response = $facebook->api('/' . self::APP_ID . '/insights');
  }

  public function testBase64UrlDecode() {
    $input = 'Facebook rocks';
    $output = 'RmFjZWJvb2sgcm9ja3M';

    self::assertEquals($input,
                       FBBase64UrlDecode::publicBase64UrlDecode($output),
                       'Expect base-64 decoded value.');
  }

  public function testSignedToken() {
    $facebook = new FBParseSignedRequest(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));

    $payload = $facebook->publicParseSignedRequest(self::$kValidSignedRequest);
    self::assertNotNull($payload, 'Expected token to parse');
    self::assertNull($facebook->getSignedRequest());
    $_REQUEST['signed_request'] = self::$kValidSignedRequest;
    self::assertEquals($payload, $facebook->getSignedRequest());
  }

  public function testNonTossedSignedtoken() {
    $facebook = new FBParseSignedRequest(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));

    $payload = $facebook->publicParseSignedRequest(
      self::$kNonTosedSignedRequest);
    self::assertNotNull($payload, 'Expected token to parse');
    self::assertNull($facebook->getSignedRequest());
    $_REQUEST['signed_request'] = self::$kNonTosedSignedRequest;
    self::assertEquals(array('algorithm' => 'HMAC-SHA256'),
      $facebook->getSignedRequest());
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
    self::assertEquals('5526183', $response['id'], 'Expect id.');
  }

  public function testVideoUpload() {
    $facebook = new FBRecordOauthRequestUrl(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));

    $facebook->api(array('method' => 'video.upload'));
    self::assertContains('//api-video.', $facebook->getRequestedUrl(),
                         'Expect video.upload to go against api-video.');
  }

  public function testGetUserAndAccessTokenFromSession() {
    $facebook = new FBSetPersistentData(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));

    $facebook->publicSetPersistentData('access_token',
                                       self::$kExpiredAccessToken);
    $facebook->publicSetPersistentData('user_id', 12345);
    self::assertEquals(self::$kExpiredAccessToken,
                       $facebook->getAccessToken(),
                       'Get access token from persistent store.');
    self::assertEquals('12345',
                       $facebook->getUser(),
                       'Get user id from persistent store.');
  }

  public function testGetUserAndAccessTokenFromSignedRequestNotSession() {
    $facebook = new FBSetPersistentData(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));

    $_REQUEST['signed_request'] = self::$kValidSignedRequest;
    $facebook->publicSetPersistentData('user_id', 41572);
    $facebook->publicSetPersistentData('access_token',
                                       self::$kExpiredAccessToken);
    self::assertNotEquals('41572', $facebook->getUser(),
                          'Got user from session instead of signed request.');
    self::assertEquals('1677846385', $facebook->getUser(),
                       'Failed to get correct user ID from signed request.');
    self::assertNotEquals(
      self::$kExpiredAccessToken,
      $facebook->getAccessToken(),
      'Got access token from session instead of signed request.');
    self::assertNotEmpty(
      $facebook->getAccessToken(),
      'Failed to extract an access token from the signed request.');
  }

  public function testGetUserWithoutCodeOrSignedRequestOrSession() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET
    ));

    // deliberately leave $_REQUEST and _$SESSION empty
    self::assertEmpty($_REQUEST,
                      'GET, POST, and COOKIE params exist even though '.
                      'they should not.  Test cannot succeed unless all of '.
                      '$_REQUEST is empty.');
    self::assertEmpty($_SESSION,
                      'Session is carrying state and should not be.');
    self::assertEmpty($facebook->getUser(),
                      'Got a user id, even without a signed request, '.
                      'access token, or session variable.');
    self::assertEmpty($_SESSION,
                      'Session superglobal incorrectly populated by getUser.');
  }

  protected static function generateMD5HashOfRandomValue() {
    return md5(uniqid(mt_rand(), true));
  }

  protected function setUp() {
    self::clearSuperGlobals();
  }

  protected static function clearSuperGlobals() {
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
  protected static function assertIsSubset($correct, $actual, $msg='') {
    foreach ($correct as $key => $value) {
      $actual_value = $actual[$key];
      $newMsg = (strlen($msg) ? ($msg.' ') : '').'Key: '.$key;
      self::assertEquals($value, $actual_value, $newMsg);
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

class FBRecordOauthRequestUrl extends TransientFacebook {
  private $url;

  protected function _oauthRequest($url, $params) {
    $this->url = $url;
  }

  public function getRequestedUrl() {
    return $this->url;
  }
}

class FBBase64UrlDecode extends TransientFacebook {
  public static function publicBase64UrlDecode($input) {
    return self::base64UrlDecode($input);
  }
}

class FBParseSignedRequest extends TransientFacebook {
  public function publicParseSignedRequest($input) {
    return $this->parseSignedRequest($input);
  }
}

class FBSetPersistentData extends Facebook {
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

class FBGetCurrentUrl extends TransientFacebook {
  public function publicGetCurrentUrl() {
    return $this->getCurrentUrl();
  }
}

class FBGetSignedRequestCookie extends TransientFacebook {
  public function publicGetSignedRequest() {
    return $this->getSignedRequest();
  }

  public function publicGetSignedRequestCookieName() {
    return $this->getSignedRequestCookieName();
  }
}

Facebook PHP SDK
================

The [Facebook Platform](http://developers.facebook.com/) is
a set of APIs that make your application more social. Read more about
[integrating Facebook with your web site](http://developers.facebook.com/docs/guides/web)
on the Facebook developer site.

This repository contains the open source PHP SDK that allows you to utilize the
above on your website. Except as otherwise noted, the Facebook PHP SDK
is licensed under the Apache Licence, Version 2.0
(http://www.apache.org/licenses/LICENSE-2.0.html)


Usage
-----

The [examples][examples] are a good place to start. The minimal you'll need to
have is:

    <?php

    require './facebook.php';

    $facebook = new Facebook(array(
      'appId'  => 'YOUR APP ID',
      'secret' => 'YOUR API SECRET',
      'cookie' => true, // enable optional cookie support
    ));

To make [API][API] calls:

    try {
      $me = $facebook->api('/me');
    } catch (FacebookApiException $e) {
      error_log($e);
    }

Logged in vs Logged out:

    if ($facebook->getSession()) {
      echo '<a href="' . $facebook->getLogoutUrl() . '">Logout</a>';
    } else {
      echo '<a href="' . $facebook->getLoginUrl() . '">Login</a>';
    }

[examples]: http://github.com/facebook/php-sdk/blob/master/examples/example.php
[API]: http://developers.facebook.com/docs/api


Feedback
--------

We are relying on the [GitHub issues tracker][issues] linked from above for
feedback. File bugs or other issues [here][issues].

[issues]: http://github.com/facebook/php-sdk/issues



Tests
-----

In order to keep us nimble and allow us to bring you new functionality, without
compromising on stability, we have ensured full test coverage of the new SDK.
We are including this in the open source repository to assure you of our
commitment to quality, but also with the hopes that you will contribute back to
help keep it stable. The easiest way to do so is to file bugs and include a
test case.

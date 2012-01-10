<?php
require 'vendor/pear/Universal/ClassLoader/BasePathClassLoader.php';
$loader = new Universal\ClassLoader\BasePathClassLoader(array( 'src' ));
$loader->register();

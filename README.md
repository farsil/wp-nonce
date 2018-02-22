# wp-nonce
[![Build Status](https://travis-ci.org/farsil/wp-nonce.svg?branch=master)](https://travis-ci.org/farsil/wp-nonce) 
[![Code Coverage](https://codecov.io/gh/farsil/wp-nonce/branch/master/graph/badge.svg)](https://codecov.io/gh/farsil/wp-nonce)

`wp-nonce` is a replacement library for wordpress nonces written in 
[PHP](https://php.net/). It aims to provide an object oriented interface that
 can be used in lieu of the wordpress `wp_nonce_*` functions.

## Installation
Add the following entry to the `required` list in your `composer.json`:
```
"farsil/wp-nonce": "v1.0.*"
```
Or, alternatively, run:
```
$ composer require farsil/wp-nonce
```

## Usage
Nonce generation is performed through the `Nonce_Generator` class, and nonce 
validation is performed through the `Nonce_Validator` class. The method names
are reminiscent of the corresponding methods of the Wordpress core 
functions, and behave similarly, with a few differences. See the 
documentation for additional details.

## Example
```
<?php
// We don't need to load themes
define( 'WP_USE_THEMES', false );

// This line assumes your Wordpress installation is in your PHP include path,
// change accordingly if it is not the case.
require_once 'wp-load.php';

// Let composer autoload wp-nonce classes.
require_once 'vendor/autoload.php';

// Generate a new nonce. Default lifetime is 1 day.
$gen = new Wordpress\Nonce_Generator( 'test-nonce' );
$token = $gen->generate();

// In order to properly validate the generated token, the constructor parameters
// need to match those used in Nonce_Generator.
$val = new Wordpress\Nonce_Validator( 'test-nonce' );
echo $val->verify( $token );
```
Expected Output:
```
1
```

## Tests
`wp-nonce` includes a comprehensive PHPUnit test suite. Since `wp-nonce` 
includes a `phpunit.xml.dist` file, all you need to do is to navigate to the 
project root, and run:
```
$ php /path/to/phpunit.phar --include-path=/path/to/wordpress
```
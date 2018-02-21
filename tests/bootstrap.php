<?php

// Add wordpress installation directory to PHPUnit's --include-path
define( 'WP_USE_THEMES', false );
require_once "wp-load.php";

// Composer takes care of autoloading our classes
require_once __DIR__ . "/../vendor/autoload.php";
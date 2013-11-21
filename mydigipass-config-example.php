<?php
// ** MYDIGIPASS.COM configuration ** //
//
// Copy this file to 'mydigipass-config.php' and fill
// in the data received from https://developer.mydigipass.com
//
define('CLIENT_ID',     '<your-client-id>');
define('CLIENT_SECRET', '<your-client-secret>');
define('REDIRECT_URI',  'http://localhost/php-mydigipass/index.php');

# Change this parameter to https://www.mydigipass.com when going into production.
define('MDP_BASE_URI', 'https://sandbox.mydigipass.com');

?>

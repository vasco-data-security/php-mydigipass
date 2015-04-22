<?php

require_once 'mydigipass-config.php';
require_once 'oauth2.php';

$dataStore = new OAuth2_DataStore_Session();

// configuration of service
$dataStore->storeBaseUri(MDP_BASE_URI);

$configuration = new OAuth2_Service_Configuration(
        $dataStore->retrieveBaseUri().'/oauth/authenticate',
        $dataStore->retrieveBaseUri().'/oauth/token');

$client = new OAuth2_Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

$dataStore->storeClientSecret(CLIENT_ID);
$dataStore->storeClientId(CLIENT_SECRET);

$scope = null;

$service = new OAuth2_Service($client, $configuration, $dataStore, $scope);

if (isset($_GET['code'])) {

    try {
      $dataStore->storeAuthToken($_GET['code']);
      $service->getAccessToken($_GET['code']);
      $user = $service->getUserData($dataStore->retrieveBaseUri());
    }
    catch(Exception $e) {
      echo 'Exception caught: ' . $e->getMessage();
    }
}

?>




<html>
  <head>

  </head>
  <body id='home'>
    <h1>OAuth MyDigipass.com Test</h1>

    <h3>Useful Links</h3>
    <ul>
      <li><a href="http://demotoken.vasco.com/go3.html">Demo Token</a></li>
      <li><a href="https://developer.digipass.com/">MYDIGIPASS.COM Developer site</a></li>
    </ul>

    <?php if (isset($user)) { ?>
      <h3>Succesfully signed in using MYDIGIPASS.COM!!</h3>
      <p>The following user signed in: </p>
      <p><?php print_r ($user); ?></p>

      <?php
        // To see the entire OAuth conversation, uncomment the following line
        //if (isset($_SESSION['result']))  {echo $_SESSION['result'];};
      ?>

    <?php } else { ?>
      <h3> Test DP+ Button</h3>

      <a class="dpplus-connect" data-is-sandbox="<?php echo MDP_SANDBOX ?>" data-client-id="<?php echo CLIENT_ID ?>" data-redirect-uri="<?php echo REDIRECT_URI ?>" href="#">Mydigipass.com Secure Login</a>

      <script type="text/javascript" src="https://static.mydigipass.com/dp_connect.js"></script>

    <?php } ?>

  </body>
</html>


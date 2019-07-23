<?php

namespace Polevaultweb\WPOAuth2\Clients;

use Polevaultweb\WPOAuth2\OAuth2Client;

class Google extends OAuth2Client {

	protected $authorization_url = 'https://accounts.google.com/o/oauth2/v2/auth';
}

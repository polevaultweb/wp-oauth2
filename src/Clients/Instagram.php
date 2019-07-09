<?php

namespace Polevaultweb\WPOAuth2\Clients;

use Polevaultweb\WPOAuth2\OAuth2Client;

class Instagram extends OAuth2Client {

	protected $authorization_url = 'https://api.instagram.com/oauth/authorize/';
}

<?php

namespace Polevaultweb\WPOAuth2\Clients;

use Polevaultweb\WPOAuth2\OAuth2Client;

class Dropbox extends OAuth2Client {

	protected $authorization_url = 'https://www.dropbox.com/oauth2/authorize';
}

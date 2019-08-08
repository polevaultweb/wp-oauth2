<?php

namespace Polevaultweb\WPOAuth2;

class TokenManager {

	public function remove_access_token( $provider ) {
		$token = new AccessToken( $provider );
		$token->delete();
	}

	public function get_access_token( $provider, $type = 'token' ) {
		$token = new AccessToken( $provider );

		return $token->get( $type );
	}

	public function get_refresh_token( $provider ) {
		$token = new AccessToken( $provider );

		return $token->get( 'refresh_token' );
	}

	public function set_access_token( $provider, $token, $refresh_token = null ) {
		$token = new AccessToken( $provider, $token, $refresh_token );
		$token->save();
	}
}
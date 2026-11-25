<?php

use PHPUnit\Framework\TestCase;
use Polevaultweb\WPOAuth2\V3\WPOAuth2;

/**
 * Resets the stubs, both copies' instances and the request between tests, and
 * plays the proxy's part in a login.
 */
abstract class WPOAuth2_TestCase extends TestCase {

	const PROXY = 'https://l.example.test/';

	const PROVIDER = 'instagram-facebook';

	protected function setUp(): void {
		WP_Stubs::reset();
		Test_Admin_Handler::$query = array();
		$this->reset_static( WPOAuth2::class, 'instances', array() );
		$this->reset_static( Polevaultweb\WPOAuth2\WPOAuth2::class, 'instance', null );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['pagenow'] );
	}

	private function reset_static( $class, $property, $value ) {
		$reflection = new ReflectionProperty( $class, $property );
		$reflection->setAccessible( true );
		$reflection->setValue( null, $value );
	}

	/**
	 * @param string $url
	 *
	 * @return array
	 */
	protected function query( $url ) {
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $query );

		return $query;
	}

	/**
	 * Be on an admin page, with these query args.
	 *
	 * @param string $url
	 */
	protected function visit( $url ) {
		$GLOBALS['pagenow']        = basename( parse_url( $url, PHP_URL_PATH ) );
		Test_Admin_Handler::$query = $this->query( $url );
	}

	/**
	 * Where the proxy sends the browser back to after a login started from
	 * $authorize_url: the redirect_uri, with the token encrypted with the key.
	 *
	 * @param string $authorize_url
	 * @param string $token
	 * @param array  $extra Eg. 'expires'
	 *
	 * @return string
	 */
	protected function proxy_callback( $authorize_url, $token, $extra = array() ) {
		$params = $this->query( $authorize_url );
		$iv     = random_bytes( openssl_cipher_iv_length( $params['method'] ) );

		$args = array_merge(
			array(
				'wp-oauth2' => self::PROVIDER,
				'action'    => 'connect',
				'token'     => openssl_encrypt( $token, $params['method'], $params['key'], 0, $iv ),
				// The proxy urlencodes the IV, then http_build_query() encodes it again
				'iv'        => urlencode( $iv ),
			),
			$extra
		);

		return add_query_arg( $args, $params['redirect_uri'] );
	}
}

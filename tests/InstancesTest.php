<?php

use Polevaultweb\WPOAuth2\V3\WPOAuth2;

/**
 * WPOAuth2::instance() gives each instance key its own instance.
 */
class InstancesTest extends WPOAuth2_TestCase {

	public function test_each_key_gets_its_own_instance() {
		$pro  = WPOAuth2::instance( self::PROXY, Test_Pro_Token::class, 'instagrate_pro' );
		$lite = WPOAuth2::instance( self::PROXY, Test_Lite_Token::class, 'intagrate_lite' );

		$this->assertNotSame( $pro, $lite );
		$this->assertNotSame( $pro->token_manager, $lite->token_manager );
		$this->assertSame( 'instagrate_pro', $pro->get_instance_key() );
		$this->assertSame( 'intagrate_lite', $lite->get_instance_key() );
	}

	public function test_the_same_key_gets_the_same_instance() {
		$first  = WPOAuth2::instance( self::PROXY, Test_Pro_Token::class, 'instagrate_pro' );
		$second = WPOAuth2::instance( 'https://other.example.test/', Test_Lite_Token::class, 'instagrate_pro' );

		$this->assertSame( $first, $second );
		$this->assertSame( self::PROXY, $second->get_oauth_proxy_url() );
	}

	public function test_key_defaults_to_the_token_class() {
		$pro  = WPOAuth2::instance( self::PROXY, Test_Pro_Token::class );
		$lite = WPOAuth2::instance( self::PROXY, Test_Lite_Token::class );

		$this->assertSame( 'test_pro_token', $pro->get_instance_key() );
		$this->assertSame( 'test_lite_token', $lite->get_instance_key() );
		$this->assertNotSame( $pro, $lite );
	}

	public function test_key_without_a_token_class_is_default() {
		$this->assertSame( WPOAuth2::DEFAULT_INSTANCE, WPOAuth2::instance( self::PROXY )->get_instance_key() );
	}

	/**
	 * @dataProvider keys
	 */
	public function test_keys_are_sanitized( $key, $expected ) {
		$this->assertSame( $expected, WPOAuth2::sanitize_instance_key( $key ) );
	}

	public function keys() {
		return array(
			'slug'             => array( 'instagrate_pro', 'instagrate_pro' ),
			'hyphens'          => array( 'my-plugin', 'my-plugin' ),
			'upper case'       => array( 'Intagrate Lite!', 'intagrate_lite' ),
			'namespaced class' => array( '\\Vendor\\Plugin\\Token', 'vendor_plugin_token' ),
			'empty'            => array( '', 'default' ),
			'only symbols'     => array( '!!!', 'default' ),
			'too long'         => array( str_repeat( 'a', 65 ), md5( str_repeat( 'a', 65 ) ) ),
		);
	}

	public function test_filter_and_transient_names_include_the_key() {
		$pro = WPOAuth2::instance( self::PROXY, Test_Pro_Token::class, 'instagrate_pro' );

		$this->assertSame( 'pvw_wp_oauth2_instagrate_pro_redirect_url', $pro->get_filter_name( 'redirect_url' ) );
		$this->assertSame( 'wp-oauth2-key-instagrate_pro', WPOAuth2::login_key_transient( 'instagrate_pro' ) );
	}
}

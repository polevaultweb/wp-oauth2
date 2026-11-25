<?php

namespace Polevaultweb\WPOAuth2;

interface AccessTokenInterface {

	public function save();

	public function delete();

	public function get_token();

	public function get_refresh_token();
}

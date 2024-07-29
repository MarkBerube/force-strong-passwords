<?php

/**
 * Mock of WP's apply_filters function
 * @return mixed
 */
function apply_filters() {
	return TestStrongPasswordManager::$apply_filters_result;
}

/**
 * Mock of WP's sanitize_text_field function
 * @return mixed
 */
function sanitize_text_field($arg) {
	return $arg;
}

/**
 * Mock of WP's sanitize_field function
 * @return void
 */
function sanitize_key() {}

/**
 * Mock of WP's is_network_admin function
 * @return mixed
 */
function is_network_admin() {
	return TestStrongPasswordManager::$is_network_admin_result;
}

/**
 * Mock of WP's user_can function
 * @return mixed
 */
function user_can() {
	return TestStrongPasswordManager::$user_can_result;
}

function wp_verify_nonce() {
	return true;
}

define( 'MB_FSP_COMMON_PASSWORD_FILE', 'test.txt' );
define( 'MB_FSP_WEAK_ROLES', 'subscriber,contributor' );
define( 'MB_FSP_CAPS_CHECK', 'publish_posts,upload_files,edit_published_posts' );

class Mock_WP_File_System {
	public function exists(): bool {
		return true;
	}

	public function get_contents(): string
	{
		return 'password1'.PHP_EOL;
	}
}

require_once __DIR__ . '/includes/class-mb-strong-password-manager.php';

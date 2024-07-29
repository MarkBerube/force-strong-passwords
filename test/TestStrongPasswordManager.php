<?php
/**
 * WP plugin that enforces strong passwords for privileged users
 *
 * @package WordPress
 * @since 2.0.0
 */

/**
 * Class TestStrongPasswordManager
 * Tests for the strong password manager class
 */
class TestStrongPasswordManager extends PHPUnit\Framework\TestCase {
	/**
	 * Mock value for mock WP function is_network_admin
	 *
	 * @var bool
	 */
	public static $is_network_admin_result = false;

	/**
	 * Mock value for mock WP function user_can
	 *
	 * @var bool
	 */
	public static $user_can_result = false;

	/**
	 * Testing that passwords are evaluated correctly
	 *
	 * @return void
	 */
	public function test_is_strong_password_validation() {
		global $wp_filesystem;
		$wp_filesystem = new Mock_WP_File_System();

		$user = 'mark';

		$this->assertFalse( MB_Strong_Password_Manager::is_strong_password( 'not7', $user ) );
		$this->assertFalse( MB_Strong_Password_Manager::is_strong_password( 'ALLCAPS78', $user ) );
		$this->assertFalse( MB_Strong_Password_Manager::is_strong_password( 'nocaps78', $user ) );
		$this->assertFalse( MB_Strong_Password_Manager::is_strong_password( '123456789', $user ) );
		$this->assertFalse( MB_Strong_Password_Manager::is_strong_password( 'aaabcdefgh123', $user ) );
		$this->assertTrue( MB_Strong_Password_Manager::is_strong_password( 'realGoodPassword123456', $user ) );
		$this->assertFalse( MB_Strong_Password_Manager::is_strong_password( 'password1', $user ) );
		$this->assertFalse( MB_Strong_Password_Manager::is_strong_password( 'markMarkmark123', 'markMarkmark123' ) );
	}

	/**
	 * Testing for if the strong password is required (network admin screen, admin role, etc.)
	 *
	 * @return void
	 */
	public function test_should_enforce_strong_password() {
		self::$is_network_admin_result = true;
		$this->assertTrue( MB_Strong_Password_Manager::should_enforce_strong_password( 1 ) );

		self::$is_network_admin_result = false;
		$this->assertFalse( MB_Strong_Password_Manager::should_enforce_strong_password( false, array( 'subscriber' ) ) );

		self::$user_can_result = true;
		$this->assertTrue( MB_Strong_Password_Manager::should_enforce_strong_password( false, array( 'admin' ) ) );
	}

	/**
	 * Testing that parsing data found in POST fields works as intended
	 *
	 * @return void
	 */
	public function test_parse_user_data() {
		$_POST = array(
			'pass1'       => 'password1',
			'pass1_nonce' => '123',
			'role'        => 'subscriber',
			'user_login'  => 'mark',
		);

		$user_data_mock     = new stdClass();
		$user_data_mock->ID = 1;

		$this->assertTrue(
			MB_Strong_Password_Manager::parse_user_data( $user_data_mock ) === array( 'password1', 'subscriber', 1, 'mark' )
		);
	}
}

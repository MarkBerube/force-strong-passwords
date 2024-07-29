<?php
/**
 * WP plugin that enforces strong passwords for privileged users
 *
 * @package WordPress
 * @since 2.0.0
 *
 * @phpcs:disable WordPress.Security.ValidatedSanitizedInput
 * @phpcs:disable WordPress.Security.NonceVerification
 */

/**
 * Class MB_Strong_Password_Manager
 * Determines whether the password is strong or not
 */
class MB_Strong_Password_Manager {
	/**
	 * Functionality used by both user profile and reset password validation.
	 *
	 * @param WP_Error $errors WordPress error object.
	 * @param stdClass $user_data WordPress User object.
	 * @return WP_Error
	 */
	public static function validate_strong_password( $errors, $user_data ) {
		list( $password, $role, $user_id, $user_name ) = self::parse_user_data( $user_data );

		if ( ( false === $password ) ||
			( is_wp_error( $errors ) &&
				$errors->get_error_data( 'pass' ) )
		) {
			return $errors;
		}

		if ( self::should_enforce_strong_password( $user_id, $role ) ) {
			if (
				! self::is_strong_password( $password, $user_name ) &&
				is_wp_error( $errors )
			) { // Is this a WP error object?
				$errors->add( 'pass', apply_filters( 'mb_fsp_error_message', __( '<strong>ERROR</strong>: Please make the password a strong one.', 'mb-force-strong-passwords' ) ) );
			}
		}

		return $errors;
	}

	/**
	 * Parses user data from $user_data object or $_POST global from WP form
	 *
	 * @param stdClass $user_data WordPress user object.
	 * @return array
	 */
	public static function parse_user_data( $user_data ): array {
		$password  = ( isset( $_POST['pass1'], $_POST['pass1_nonce'] ) && wp_verify_nonce( sanitize_key( $_POST['pass1_nonce'] ) && trim( $_POST['pass1'] ) ) ? sanitize_text_field( $_POST['pass1'] ) : false );
		$role      = isset( $_POST['role'] ) ? sanitize_text_field( $_POST['role'] ) : false;
		$user_id   = isset( $user_data->ID ) ? sanitize_text_field( $user_data->ID ) : false;
		$user_name = isset( $_POST['user_login'] ) ? sanitize_text_field( $_POST['user_login'] ) : $user_data->user_login;

		return array( $password, $role, $user_id, $user_name );
	}

	/**
	 * Checks whether the given WP user should be forced to have a strong password.
	 *
	 * @param int    $user_id WordPress user ID to check.
	 * @param string $role WordPress user's role to check.
	 * @return bool
	 */
	public static function should_enforce_strong_password( $user_id, $role = false ): bool {
		// Force strong passwords from network admin screens.
		if ( is_network_admin() ) {
			return true;
		}

		// We couldn't find a user ID, use the role instead.
		if ( false === $user_id && false !== $role ) {
			$weak_roles = explode( ',', MB_FSP_WEAK_ROLES );
			if ( ! empty( $weak_roles ) && in_array( $role, $weak_roles, true ) ) {
					return false;
			}
		}

		$check_caps = explode( ',', MB_FSP_CAPS_CHECK );

		if ( ! empty( $check_caps ) ) {
			foreach ( $check_caps as $cap ) {
				if ( user_can( $user_id, $cap ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Fetches a list of  common compromised passwords from the Nation Cyber Security Centre
	 *
	 * @return array
	 */
	public static function fetch_common_password_list(): array {
		global $wp_filesystem;

		if ( ! $wp_filesystem->exists( MB_FSP_COMMON_PASSWORD_FILE ) ) {
			return array();
		}

		return explode( PHP_EOL, $wp_filesystem->get_contents( MB_FSP_COMMON_PASSWORD_FILE ) );
	}


	/**
	 * Determines if a password is strong enough
	 *
	 * @param string $password Password to compare against.
	 * @param string $username Username to compare against.
	 * @return bool
	 */
	public static function is_strong_password( $password, $username ): bool {
		$length = strlen( $password );

		// Password is at least 8 characters in length & does not match the username.
		if ( $length < 8 || $username === $password ) {
			return false;
		}

		// Here's some more rigorous char checks for a strong password.
		list( $lower, $upper, $digit, $repeat) = array( false, false, false, true );

		/**
		 * Iterate over each character in the password for the following rules:
		 * - contains  at least one lowercase letter and at least one uppercase letter
		 * - contains at least one digit
		 * - doesn't repeat characters 3 times in a row
		 */
		$char_count = 0;
		for ( $i = 0; $i < $length; $i++ ) {
			if ( $i > 0 && $password[ $i ] === $password[ $i - 1 ] ) {
				++$char_count;

				if ( $char_count > 2 ) {
					$repeat = false;
				}
			} else {
				$char_count = 1;
			}

			if ( ctype_lower( $password[ $i ] ) ) {
				$lower = true;
			} elseif ( ctype_upper( $password[ $i ] ) ) {
				$upper = true;
			} elseif ( ctype_digit( $password[ $i ] ) ) {
				$digit = true;
			}
		}

		if ( in_array( false, array( $lower, $upper, $digit, $repeat ), true ) ) {
			return false;
		}

		$pw_array = self::fetch_common_password_list();
		// Check if the password is in the common password list.
		if ( array_search( $password, $pw_array, true ) !== false ) {
			return false;
		}

		return true;
	}
}

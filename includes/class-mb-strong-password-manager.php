<?php

class MB_Strong_Password_Manager {
    /**
     * Functionality used by both user profile and reset password validation.
     */
    public static function validate_strong_password( $errors, $user_data )
    {
        list( $password, $role, $user_id, $user_name ) = self::parse_user_data( $user_data );

        if ( ( false === $password ) ||
            ( is_wp_error( $errors ) &&
                $errors->get_error_data( 'pass' ) )
        ) {
            return $errors;
        }

        if ( self::should_enforce_strong_password( $user_id, $role ) ) {
            if (
                !self::is_strong_password( $password, $user_name ) &&
                is_wp_error( $errors )
            ) { // Is this a WP error object?
                $errors->add( 'pass', apply_filters( 'mb_fsp_error_message', __( '<strong>ERROR</strong>: Please make the password a strong one.', 'mb-force-strong-passwords' ) ) );
            }
        }

        return $errors;
    }

    /**
     * Parses user data from $user_data object or $_POST global from WP form
     * @param $user_data
     * @return array
     */
    public static function parse_user_data( $user_data ): array {
        $password    = ( isset( $_POST['pass1'] ) && trim( $_POST['pass1'] ) ) ? sanitize_text_field( $_POST['pass1'] ) : false;
        $role        = isset( $_POST['role'] ) ? sanitize_text_field( $_POST['role'] ) : false;
        $user_id     = isset( $user_data->ID ) ? sanitize_text_field( $user_data->ID ) : false;
        $user_name    = isset( $_POST['user_login'] ) ? sanitize_text_field( $_POST['user_login'] ) : $user_data->user_login;

        return [ $password, $role, $user_id, $user_name ];
    }

    /**
     * Checks whether the given WP user should be forced to have a strong password.
     * @param $user_id
     * @param $role
     * @return bool
     */
    public static function should_enforce_strong_password( $user_id, $role = false ): bool
    {
        // Force strong passwords from network admin screens.
        if ( is_network_admin() ) {
            return true;
        }

        // couldn't find a user ID, use role instead
        if ( $user_id === false && $role !== false ) {
            $weak_roles = explode( ',', MB_FSP_WEAK_ROLES );
            if ( ! empty( $weak_roles ) && in_array( $role, $weak_roles ) ) {
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
     * Determines if a password is strong enough
     * @param $password
     * @param $username
     * @return bool
     */
    public static function is_strong_password( $password, $username ): bool
    {
        // is at least 8 characters in length & does not match the username
        if ( strlen($password) > 8 ||  $username === $password ) {
            return false;
        }

        // more rigorous checks for a strong password
        list( $lower, $upper, $digit, $repeat, $compromised ) = array_fill( 0, 5, false );

        /**
         * iterate over each character in the password for the following rules:
         * - contains  at least one lowercase letter and at least one uppercase letter
         * - contains at least one digit
         */
        $char_count = 0;
        for ( $i = 0; $i < strlen( $password ); $i++ ) {
            if ( $i > 0 && $password[ $i ] == $password[ $i - 1 ] ) {
                $char_count++;
            } else {
                $char_count = 1;
            }

            if ( ctype_lower( $password[ $i ] ) ) {
                $lower = true;
            } elseif ( ctype_upper( $password[ $i ] ) ) {
                $upper = true;
            } elseif ( ctype_digit( $password[ $i ] ) ) {
                $digit = true;
            } elseif ( $char_count > 3 ) {
                $repeat = true;
            }
        }

        // check if the password is in the common password list
        if ( $fp = @fopen( MB_FSP_COMMON_PASSWORD_FILE, 'r' ) ) {
            $array = explode( PHP_EOL, fread($fp, filesize( MB_FSP_COMMON_PASSWORD_FILE ) ) );

            if ( array_search( $password, $array ) !== false ) {
                $compromised = true;
            }

            fclose( $fp );
        }

        // if any checks on the password are true, that means the password isn't strong enough
        return ! in_array( true, [ $lower, $upper, $digit, $repeat, $compromised ] );
    }
}
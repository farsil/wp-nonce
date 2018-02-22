<?php

namespace Wordpress;

/**
 * Class Nonce_Validator provides methods to validate cryptographic tokens.
 * @package Wordpress
 */
class Nonce_Validator extends Nonce_Hasher {
    /**
     * Nonce_Validator Constructor.
     *
     * To correctly validate nonces, these parameters needs to be specular of
     * those passed in the constructor of NonceGenerator.
     *
     * @param string|int $action Scalar value to add context to the
     * nonce. Default '-1'.
     * @param int $lifetime [optional] The validity interval of created
     * nonces, in seconds. Default is DAY_IN_SECONDS (86400, one day).
     * @param \WP_User $user [optional] User object, used to add context to the
     * nonce. Default wp_get_current_user().
     * @param string $token [optional] Session token, used to add context to the
     * nonce. Default wp_get_session_token().
     */
    public function __construct(
        $action, int $lifetime = DAY_IN_SECONDS,
        \WP_User $user = null, string $token = null
    ) {
        parent::__construct( $action, $lifetime, $user, $token );
    }

    /**
     * Makes sure that a user was referred from another admin page.
     *
     * To avoid security exploits.
     *
     * @throws Auth_Exception Thrown if validation fails, and the user does
     * not come from an another admin page.
     *
     * @param string $query_arg [optional] Key to check for nonce in
     * `$_REQUEST`. Default '_wpnonce'.
     *
     * @return false|int False if the nonce is invalid, 1 if the nonce is valid
     * and generated in the first half of its lifetime, 2 if the nonce is valid
     * and generated in the second half of its lifetime.
     */
    public function check_admin_referer( string $query_arg = '_wpnonce' ) {
        $admin_url = strtolower( admin_url() );
        $referer   = strtolower( wp_get_referer() );

        $result = isset( $_REQUEST[ $query_arg ] ) ?
            $this->verify( $_REQUEST[ $query_arg ] ) : false;

        do_action( 'check_admin_referer', $this->get_action(), $result );

        if ( ! $result && strpos( $referer, $admin_url ) !== 0 ) {
            throw new Auth_Exception( $this->get_action(),
                'Referer does not come from an admin URL.'
            );
        }

        return $result;
    }

    /**
     * Verify that correct nonce was used with time limit.
     *
     * The user is given an amount of time to use the token, so therefore,
     * since the UID and $action remain the same, the independent variable is
     * the time.
     *
     * @param string $nonce Nonce that was used in the form to verify.
     *
     * @return false|int False if the nonce is invalid, 1 if the nonce is valid
     * and generated in the first half of its lifetime, 2 if the nonce is valid
     * and generated in the second half of its lifetime.
     */
    public function verify( string $nonce ) {
        $nonce = (string) $nonce;
        if ( empty( $nonce ) ) {
            return false;
        }

        $tick = $this->tick();
        if ( hash_equals( $this->get_nonce( $tick ), $nonce ) ) {
            return 1;
        }
        if ( hash_equals( $this->get_nonce( $tick - 1 ), $nonce ) ) {
            return 2;
        }

        do_action(
            'wp_verify_nonce_failed',
            $nonce, $this->get_action(), $this->get_user(), $this->get_token()
        );

        return false;
    }

    /**
     * Verifies the Ajax request to prevent processing requests external of the
     * blog.
     *
     * @param false|string $query_arg [optional] Key to check for the nonce in
     * `$_REQUEST`. If false, `$_REQUEST` values will be evaluated for
     * '_ajax_nonce', and '_wpnonce' (in that order). Default false.
     *
     * @return false|int False if the nonce is invalid, 1 if the nonce is valid
     * and generated in the first half of its lifetime, 2 if the nonce is valid
     * and generated in the second half of its lifetime.
     */
    public function check_ajax_referer( $query_arg = false ) {
        $nonce = '';

        if ( $query_arg && isset( $_REQUEST[ $query_arg ] ) ) {
            $nonce = $_REQUEST[ $query_arg ];
        } elseif ( isset( $_REQUEST['_ajax_nonce'] ) ) {
            $nonce = $_REQUEST['_ajax_nonce'];
        } elseif ( isset( $_REQUEST['_wpnonce'] ) ) {
            $nonce = $_REQUEST['_wpnonce'];
        }

        $result = $this->verify( $nonce );
        do_action( 'check_ajax_referer', $this->get_action(), $result );

        return $result;
    }
}

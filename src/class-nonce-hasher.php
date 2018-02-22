<?php

namespace Wordpress;

/**
 * Class Nonce_Hasher provides methods to handle cryptographic nonces. It is the
 * base class of NonceGenerator and NonceValidator, and is not necessary to
 * instantiate explicitly.
 * @package Wordpress
 */
class Nonce_Hasher {
    /**
     * User object, used to add context to the nonces.
     *
     * @var \WP_User
     */
    private $user;

    /**
     * Session token, used to add context to the nonces.
     *
     * @var string
     */
    private $token;


    /**
     * The validity interval of nonces, in seconds.
     *
     * @var int
     */
    private $lifetime;

    /**
     * Scalar value to add context to the nonces.
     *
     * @var string|int
     */
    private $action;

    /**
     * Nonce_Hasher Constructor.
     *
     * @param string|int $action [optional] Scalar value to add context to the
     * nonces. Default '-1'.
     * @param int $lifetime [optional] The validity interval of nonces, in
     * seconds. Default is DAY_IN_SECONDS (86400, one day).
     * @param \WP_User $user [optional] User object, used to add context to the
     * nonces. Default wp_get_current_user().
     * @param string $token [optional] Session token, used to add context to the
     * nonces. Default wp_get_session_token().
     */
    public function __construct(
        $action = - 1, int $lifetime = DAY_IN_SECONDS,
        \WP_User $user = null, string $token = null
    ) {
        $this->user     = $user ?: wp_get_current_user();
        $this->token    = $token ?: wp_get_session_token();
        $this->action   = $action;
        $this->lifetime = $lifetime;
    }

    /**
     * Returns the value used to add context to the nonces.
     *
     * @return string|int The action.
     */
    public function get_action() {
        return $this->action;
    }

    /**
     * Returns the validity interval of nonces.
     *
     * @return int The lifetime.
     */
    public function get_lifetime(): int {
        return $this->lifetime;
    }

    /**
     * Returns the user object used to add context to the nonces.
     *
     * @return \WP_User The user object.
     */
    public function get_user(): \WP_User {
        return $this->user;
    }

    /**
     * Returns the session token used to add context to the nonces.
     *
     * @return string The session token.
     */
    public function get_token(): string {
        return $this->token;
    }

    /**
     * Get the time-dependent variable for nonce creation.
     *
     * A nonce has a lifespan of two ticks. Nonces in their second tick may be
     * updated, e.g. by autosave.
     *
     * @return float Float value rounded up to the next highest integer.
     */
    public function tick() {
        $lifetime = apply_filters( 'nonce_life', $this->lifetime );

        return ceil( time() / ( $lifetime / 2 ) );
    }

    /**
     * Creates a nonce. If $tick is the same, it is guaranteed to return the
     * same nonce.
     *
     * @param $tick int The time-dependent variable for nonce creation.
     *
     * @return string The token.
     */
    protected function get_nonce( int $tick ): string {
        $uid = (int) $this->user->ID;
        if ( ! $uid ) {
            $uid = apply_filters( 'nonce_user_logged_out',
                $uid, $this->action );
        }

        return self::hash( $tick . '|' . $this->action . '|' . $uid .
                           '|' . $this->token );
    }

    /**
     * Hashes the provided data. It is used internally to build nonces out of
     * context information.
     *
     * @static
     *
     * @param $data string The data to be hashed.
     *
     * @return string Hash of the data.
     */
    public static function hash( $data ): string {
        return substr( wp_hash( $data, 'nonce' ), - 12, 10 );
    }
}
<?php

namespace Wordpress\Nonce;

class NonceHasher {
    private $user;
    private $token;
    private $lifetime;
    private $action;

    public function __construct(
        $action = - 1, $lifetime = DAY_IN_SECONDS,
        $user = null, $token = null
    ) {
        $this->user     = $user ?: wp_get_current_user();
        $this->token    = $token ?: wp_get_session_token();
        $this->action   = $action;
        $this->lifetime = $lifetime;
    }

    public function getAction() {
        return $this->action;
    }

    public function getLifetime() {
        return $this->lifetime;
    }

    public function getUser() {
        return $this->user;
    }

    public function getToken() {
        return $this->token;
    }

    public function tick() {
        $lifetime = apply_filters( 'nonce_life', $this->lifetime );

        return ceil( time() / ( $lifetime / 2 ) );
    }

    protected function getNonce( $tick ) {
        $uid = (int) $this->user->ID;
        if ( ! $uid ) {
            $uid = apply_filters( 'nonce_user_logged_out',
                $uid, $this->action );
        }

        return self::hash( $tick . '|' . $this->action . '|' . $uid .
                           '|' . $this->token );
    }

    public static function hash( $data ) {
        return substr( wp_hash( $data, 'nonce' ), - 12, 10 );
    }
}
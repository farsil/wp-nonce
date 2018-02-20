<?php
/**
 * Created by PhpStorm.
 * User: silver
 * Date: 2/20/18
 * Time: 7:05 PM
 */

namespace Wordpress\Nonce;

class NonceHasher
{
    private $user;
    private $token;
    private $lifetime;
    private $action;

    public function __construct($action = -1, $lifetime = DAY_IN_SECONDS,
                                $user = NULL, $token = NULL) {
        $this->user = $user ?: wp_get_current_user();
        $this->token = $token ?: wp_get_session_token();
        $this->action = $action;
        $this->lifetime = $lifetime;
    }

    public function get_action() {
        return $this->action;
    }

    public function get_lifetime() {
        return $this->lifetime;
    }

    public function get_user() {
        return $this->user;
    }

    public function get_token() {
        return $this->token;
    }

    public function tick() {
        $life = apply_filters('nonce_life', $this->lifetime);
        return ceil(time() / ($life / 2));
    }

    protected function hash($tick) {
        $uid = (int)$this->user->ID;
        if (!$uid) {
            $uid = apply_filters('nonce_user_logged_out', $uid, $this->action);
        }

        return substr(wp_hash($tick . '|' . $this->action . '|' . $uid .
            '|' . $this->token, 'nonce'), -12, 10);
    }
}
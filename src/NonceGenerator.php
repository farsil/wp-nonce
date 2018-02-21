<?php

namespace Wordpress\Nonce;

class NonceGenerator extends NonceHasher {
    public function __construct($action = -1, $lifetime = DAY_IN_SECONDS,
                                $user = NULL, $token = NULL) {
        parent::__construct($action, $lifetime, $user, $token);
    }

    public function create() {
        return $this->hash($this->tick());
    }

    public function url($action_url, $name = "_wpnonce") {
        $action_url = str_replace('&amp;', '&', $action_url);
        return esc_html(add_query_arg($name, $this->create(), $action_url));
    }

    public function field($name = "_wpnonce", $referer = true, $echo = true) {
        $name = esc_attr($name);
        $nonce_field = '<input type="hidden" id="' . $name .
            '" name="' . $name . '" value="' . $this->create() . '" />';

        if ($referer) {
            $nonce_field .= wp_referer_field(false);
        }

        if ($echo) {
            echo $nonce_field;
        }

        return $nonce_field;
    }
}

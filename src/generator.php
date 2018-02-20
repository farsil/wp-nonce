<?php
/**
 * Created by PhpStorm.
 * User: silver
 * Date: 2/20/18
 * Time: 7:07 PM
 */

namespace Wordpress\Nonce;

class NonceGenerator extends NonceHasher {
    public function __construct($action = -1, $lifetime = DAY_IN_SECONDS,
                                $user = NULL, $token = NULL) {
        parent::__construct($action, $lifetime, $user, $token);
    }

    public function create() {
        return $this->hash($this->tick());
    }

    public function url($actionurl, $name = "_wpnonce") {
        $actionurl = str_replace('&amp;', '&', $actionurl);
        return esc_html(add_query_arg($name, $this->create(), $actionurl));
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

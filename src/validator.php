<?php
/**
 * Created by PhpStorm.
 * User: silver
 * Date: 2/20/18
 * Time: 7:08 PM
 */

namespace Wordpress\Nonce;

class NonceValidator extends NonceHasher {
    public function __construct($action = -1, $lifetime = DAY_IN_SECONDS,
                                $user = NULL, $token = NULL) {
        parent::__construct($action, $lifetime, $user, $token);
    }

    public static function ays($action) {
        if ($action == "log-out") {
            $html = sprintf(
                __('You are attempting to log out of %s'),
                get_bloginfo('name')
            );
            $html .= '</p><p>';
            $redirect_to = isset($_REQUEST['redirect_to']) ?
                $_REQUEST['redirect_to'] : '';
            $html .= sprintf(
                __('Do you really want to <a href="%s">log out</a>?'),
                wp_logout_url($redirect_to)
            );
        } else {
            $html = __('Are you sure you want to do this?');
            $referer = wp_get_referer();
            if ($referer) {
                $html .= '</p><p>';
                $html .= sprintf(
                    '<a href="%s">%s</a>',
                    esc_url(remove_query_arg('updated', $referer)),
                    __('Please try again.')
                );
            }
        }

        wp_die($html, __('WordPress Failure Notice'), 403);
    }

    public function verify($nonce) {
        $nonce = (string)$nonce;
        if (empty($nonce)) {
            return false;
        }

        $tick = $this->tick();
        if (hash_equals($this->hash($tick), $nonce)) {
            return 1;
        }
        if (hash_equals($this->hash($tick - 1), $nonce)) {
            return 2;
        }

        do_action(
            'wp_verify_nonce_failed',
            $nonce, $this->get_action(), $this->get_user(), $this->get_token()
        );
        return false;
    }

    public function check_admin_referer($query_arg = "_wpnonce") {
        if ($this->get_action() == -1) {
            global $wp_version;

            _doing_it_wrong(
                __FUNCTION__,
                __('You should specify a nonce action to be verified by ' .
                    'using the first parameter.'),
                $wp_version
            );
        }

        $admin_url = strtolower(admin_url());
        $referer = strtolower(wp_get_referer());

        $result = isset($_REQUEST[$query_arg]) ?
            $this->verify($_REQUEST[$query_arg]) : false;

        do_action('check_admin_referer', $this->get_action(), $result);

        if (!$result &&
            !($this->get_action() && strpos($referer, $admin_url) === 0)) {
            parent::ays($this->get_action());
            die();
        }

        return $result;
    }

    public function check_ajax_referer($query_arg = "_wpnonce", $die = true) {
        if ($this->get_action() == -1) {
            global $wp_version;

            _doing_it_wrong(
                __FUNCTION__,
                __('You should specify a nonce action to be verified by ' .
                    'using the first parameter.'),
                $wp_version
            );
        }

        $nonce = '';

        if ($query_arg && isset($_REQUEST[$query_arg])) {
            $nonce = $_REQUEST[$query_arg];
        } elseif (isset($_REQUEST['_ajax_nonce'])) {
            $nonce = $_REQUEST['_ajax_nonce'];
        } elseif (isset($_REQUEST['_wpnonce'])) {
            $nonce = $_REQUEST['_wpnonce'];
        }

        $result = $this->verify($nonce);
        do_action('check_ajax_referer', $this->get_action(), $result);

        if ($die && $result === false) {
            if (wp_doing_ajax()) {
                wp_die(-1, 403);
            } else {
                die('-1');
            }
        }

        return $result;
    }
}
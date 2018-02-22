<?php

namespace Wordpress;

/**
 * Class NonceGenerator provides methods to generate cryptographic tokens.
 * @package Wordpress
 */
class NonceGenerator extends NonceHasher {
    /**
     * NonceGenerator Constructor.
     *
     * @param string|int $action [optional] Scalar value to add context to the
     * nonce. Default '-1'.
     * @param int $lifetime [optional] The validity interval of created
     * nonces, in seconds. Default is DAY_IN_SECONDS (86400, one day).
     * @param \WP_User $user [optional] User object, used to add context to the
     * nonce. Default wp_get_current_user().
     * @param string $token [optional] Session token, used to add context to the
     * nonce. Default wp_get_session_token().
     */
    public function __construct(
        $action = - 1, int $lifetime = DAY_IN_SECONDS,
        \WP_User $user = null, string $token = null
    ) {
        parent::__construct( $action, $lifetime, $user, $token );
    }

    /**
     * Retrieve URL with nonce added to URL query.
     *
     * @param string $action_url URL to add nonce action.
     * @param string $name [optional] Nonce name. Default '_wpnonce'.
     *
     * @return string Escaped URL with nonce action added.
     */
    public function url(
        string $action_url, string $name = "_wpnonce"
    ): string {
        $action_url = str_replace( '&amp;', '&', $action_url );

        return esc_html(
            add_query_arg( $name, $this->generate(), $action_url )
        );
    }

    /**
     * Creates a cryptographic token tied to a specific action, user, user
     * session, and window of time.
     *
     * @return string The token.
     */
    public function generate(): string {
        return $this->getNonce( $this->tick() );
    }

    /**
     * Retrieve or display nonce hidden field for forms.
     *
     * The nonce field is used to validate that the contents of the form came
     * from the location on the current site and not somewhere else. The nonce
     * does not offer absolute protection, but should protect against most
     * cases. It is very important to use nonce field in forms.
     *
     * $name is optional, but it is strongly suggested to change the default
     * name for security reasons.
     *
     * The input name will be whatever $name value you gave. The input value
     * will be the nonce creation value.
     *
     * @param string $name [optional] Nonce name. Default '_wpnonce'.
     * @param bool $referer [optional] Whether to set the referer field for
     * validation. Default true.
     * @param bool $echo [optional] Whether to display or return hidden form
     * field. Default true.
     *
     * @return string Nonce field HTML markup.
     */
    public function field(
        string $name = "_wpnonce", bool $referer = true, bool $echo = true
    ): string {
        $name        = esc_attr( $name );
        $nonce_field = '<input type="hidden" id="' . $name .
                       '" name="' . $name . '" value="' . $this->generate() .
                       '" />';

        if ( $referer ) {
            $nonce_field .= wp_referer_field( false );
        }

        if ( $echo ) {
            echo $nonce_field;
        }

        return $nonce_field;
    }
}

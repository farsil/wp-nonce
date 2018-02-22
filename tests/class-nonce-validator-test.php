<?php

use PHPUnit\Framework\TestCase;
use Wordpress\Auth_Exception;
use Wordpress\Nonce_Validator;

class Nonce_Validator_Test extends TestCase {
    public function test__construct() {
        $mock_user     = new \WP_User();
        $mock_user->ID = 2;
        $mock_token    = 'h324abc4';

        $cases = [
            [
                'validator' => new Nonce_Validator( 'test' ),
                'action'    => 'test',
                'lifetime'  => DAY_IN_SECONDS,
                'user'      => wp_get_current_user(),
                'token'     => wp_get_session_token()
            ],
            [
                'validator' => new Nonce_Validator( 'test', 20 ),
                'action'    => 'test',
                'lifetime'  => 20,
                'user'      => wp_get_current_user(),
                'token'     => wp_get_session_token()
            ],
            [
                'validator' => new Nonce_Validator( 'test', 20, $mock_user ),
                'action'    => 'test',
                'lifetime'  => 20,
                'user'      => $mock_user,
                'token'     => wp_get_session_token()
            ],
            [
                'validator' => new Nonce_Validator( 'test', 20, $mock_user,
                    $mock_token ),
                'action'    => 'test',
                'lifetime'  => 20,
                'user'      => $mock_user,
                'token'     => $mock_token
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case['validator'] instanceof Nonce_Validator ) {
                $this->assertAttributeEquals( $case['lifetime'],
                    'lifetime', $case['validator'],
                    sprintf( 'Case #%d: Lifetime not equal.', $n + 1 )
                );

                $this->assertAttributeEquals( $case['action'],
                    'action', $case['validator'],
                    sprintf( 'Case #%d: Action not equal.', $n + 1 )
                );

                $this->assertAttributeEquals( $case['user'],
                    'user', $case['validator'],
                    sprintf( 'Case #%d: User not equal.', $n + 1 )
                );

                $this->assertAttributeEquals( $case['token'],
                    'token', $case['validator'],
                    sprintf( 'Case #%d: Token not equal.', $n + 1 )
                );
            }
        }
    }

    public function test_verify() {
        $cases = [
            [
                'validator' => new Nonce_Validator( 'test' ),
                'empty'     => true,
                'result'    => false,
                'called'    => false,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => 0,
                'result'    => 1,
                'called'    => false,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => - 1,
                'result'    => 2,
                'called'    => false,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => - 2,
                'result'    => false,
                'called'    => true,
            ],
        ];

        $closure = function () use ( &$called ) {
            $called = true;
        };

        add_filter( 'wp_verify_nonce_failed', $closure );

        foreach ( $cases as $n => $case ) {
            if ( $case['validator'] instanceof Nonce_Validator ) {
                $called = false;

                if ( isset( $case['empty'] ) ) {
                    $nonce = '';
                } else {
                    $nonce = self::offset_nonce( $case['validator'],
                        $case['offset'] );
                }

                $this->assertEquals( $case['result'],
                    $case['validator']->verify( $nonce ),
                    sprintf( 'Case #%d: Verify result not equal.', $n + 1 )
                );

                if ( $case['called'] === true ) {
                    $this->assertTrue( $called, sprintf(
                            'Case #%d: Callback should have been called.',
                            $n + 1 )
                    );
                } else {
                    $this->assertFalse( $called, sprintf(
                            'Case #%d: Callback should not have been called.',
                            $n + 1 )
                    );
                }
            }
        }

        remove_filter( 'wp_verify_nonce_failed', $closure );
    }

    private static function offset_nonce( $validator, $offset = 0 ) {
        if ( $validator instanceof Nonce_Validator ) {
            return Nonce_Validator::hash(
                $validator->tick() + $offset . '|' .
                $validator->get_action() . '|' . $validator->get_user()->ID . '|' .
                $validator->get_token()
            );
        } else {
            return false;
        }
    }

    public function test_check_admin_referer() {
        $cases = [
            [
                'validator' => new Nonce_Validator( 'test' ),
                'empty'     => true,
                'result'    => false,
                'referer'   => admin_url(),
                'query_arg' => null,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => 0,
                'result'    => 1,
                'referer'   => admin_url(),
                'query_arg' => null,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => 0,
                'result'    => 1,
                'referer'   => admin_url(),
                'query_arg' => 'foo',
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => - 2,
                'result'    => false,
                'referer'   => '/invalid/referer',
                'query_arg' => null,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => - 1,
                'result'    => 2,
                'referer'   => admin_url(),
                'query_arg' => null,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => - 2,
                'result'    => false,
                'referer'   => admin_url(),
                'query_arg' => null,
            ],
        ];

        $closure = function () use ( &$called ) {
            $called = true;
        };

        add_filter( 'check_admin_referer', $closure );

        foreach ( $cases as $n => $case ) {
            if ( $case['validator'] instanceof Nonce_Validator ) {
                $called = false;

                $_SERVER['HTTP_REFERER'] = $case['referer'];

                if ( isset( $case['empty'] ) ) {
                    $nonce = '';
                } else {
                    $nonce = self::offset_nonce( $case['validator'],
                        $case['offset'] );
                }

                try {
                    if ( is_null( $case['query_arg'] ) ) {
                        $_REQUEST = [ '_wpnonce' => $nonce ];

                        $result = $case['validator']->check_admin_referer();
                    } else {
                        $_REQUEST = [ $case['query_arg'] => $nonce ];

                        $result = $case['validator']->check_admin_referer(
                            $case['query_arg']
                        );
                    }

                    if ( ! $case['result'] &&
                         strpos( $case['referer'], admin_url() ) === false ) {
                        $this->fail(
                            sprintf( 'Case #%d: AuthException ' .
                                     'should have been thrown.', $n + 1 )
                        );
                    }

                    $this->assertEquals( $case['result'], $result,
                        sprintf(
                            'Case #%d: CheckAdminReferer result not equal.',
                            $n + 1
                        )
                    );

                    $this->assertTrue( $called, sprintf(
                            'Case #%d: Callback should have been called.',
                            $n + 1 )
                    );

                } catch ( Auth_Exception $e ) {
                    if ( ! $case['result'] &&
                         strpos( $case['referer'], admin_url() ) !== false ) {
                        $this->fail(
                            sprintf( 'Case #%d: AuthException ' .
                                     'should not have been thrown.', $n + 1 )
                        );
                    }
                }
            }
        }

        remove_filter( 'check_admin_referer', $closure );
    }

    public function test_check_ajax_referer() {
        $cases = [
            [
                'validator' => new Nonce_Validator( 'test' ),
                'empty'     => true,
                'result'    => false,
                'query_arg' => false,
                'ajax_arg'  => false,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => 0,
                'result'    => 1,
                'query_arg' => false,
                'ajax_arg'  => false,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => 0,
                'result'    => 1,
                'query_arg' => false,
                'ajax_arg'  => true,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => 0,
                'result'    => 1,
                'query_arg' => 'foo',
                'ajax_arg'  => false,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => - 1,
                'result'    => 2,
                'query_arg' => false,
                'ajax_arg'  => false,
            ],
            [
                'validator' => new Nonce_Validator( 'test' ),
                'offset'    => - 2,
                'result'    => false,
                'query_arg' => false,
                'ajax_arg'  => false,
            ],
        ];

        $closure = function () use ( &$called ) {
            $called = true;
        };

        add_filter( 'check_ajax_referer', $closure );

        foreach ( $cases as $n => $case ) {
            if ( $case['validator'] instanceof Nonce_Validator ) {
                $called = false;

                if ( isset( $case['empty'] ) ) {
                    $nonce = '';
                } else {
                    $nonce = self::offset_nonce( $case['validator'],
                        $case['offset'] );
                }

                if ( $case['query_arg'] === false ) {
                    if ( $case['ajax_arg'] ) {
                        $_REQUEST = [ '_ajax_nonce' => $nonce ];
                    } else {
                        $_REQUEST = [ '_wpnonce' => $nonce ];
                    }

                    $result = $case['validator']->check_ajax_referer( false );
                } else {
                    $_REQUEST = [ $case['query_arg'] => $nonce ];

                    $result = $case['validator']->check_ajax_referer(
                        $case['query_arg']
                    );
                }

                $this->assertEquals( $case['result'], $result,
                    sprintf(
                        'Case #%d: CheckAjaxReferer result not equal.',
                        $n + 1
                    )
                );

                $this->assertTrue( $called, sprintf(
                        'Case #%d: Callback should have been called.',
                        $n + 1 )
                );
            }
        }

        remove_filter( 'check_ajax_referer', $closure );
    }
}

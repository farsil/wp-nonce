<?php

use PHPUnit\Framework\TestCase;
use Wordpress\Nonce_Hasher;

class Nonce_Hasher_Test extends TestCase {
    public function test__construct() {
        $mock_user     = new \WP_User();
        $mock_user->ID = 2;
        $mock_token    = 'h324abc4';

        $cases = [
            [
                'hasher'   => new Nonce_Hasher( 'test' ),
                'action'   => 'test',
                'lifetime' => DAY_IN_SECONDS,
                'user'     => wp_get_current_user(),
                'token'    => wp_get_session_token()
            ],
            [
                'hasher'   => new Nonce_Hasher( 'test', 20 ),
                'action'   => 'test',
                'lifetime' => 20,
                'user'     => wp_get_current_user(),
                'token'    => wp_get_session_token()
            ],
            [
                'hasher'   => new Nonce_Hasher( 'test', 20, $mock_user ),
                'action'   => 'test',
                'lifetime' => 20,
                'user'     => $mock_user,
                'token'    => wp_get_session_token()
            ],
            [
                'hasher'   => new Nonce_Hasher( 'test', 20, $mock_user,
                    $mock_token ),
                'action'   => 'test',
                'lifetime' => 20,
                'user'     => $mock_user,
                'token'    => $mock_token
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case['hasher'] instanceof Nonce_Hasher ) {
                $this->assertAttributeEquals( $case['lifetime'],
                    'lifetime', $case['hasher'],
                    sprintf( 'Case #%d: Lifetime not equal.', $n + 1 )
                );

                $this->assertAttributeEquals( $case['action'],
                    'action', $case['hasher'],
                    sprintf( 'Case #%d: Action not equal.', $n + 1 )
                );

                $this->assertAttributeEquals( $case['user'],
                    'user', $case['hasher'],
                    sprintf( 'Case #%d: User not equal.', $n + 1 )
                );

                $this->assertAttributeEquals( $case['token'],
                    'token', $case['hasher'],
                    sprintf( 'Case #%d: Token not equal.', $n + 1 )
                );
            }
        }
    }

    public function test_hash() {
        $cases = [
            [
                'data'     => '123456',
                'expected' => 'd35bf48257',
            ],
            [
                'data'     => 'foobar',
                'expected' => '8f97159999',
            ],
            [
                'data'     => 'abcdef',
                'expected' => '56ea0275cb',
            ],
        ];

        foreach ( $cases as $n => $case ) {
            $this->assertEquals( $case['expected'],
                Nonce_Hasher::hash( $case['data'] ),
                sprintf( 'Case #%d: Hash result not equal.', $n + 1 )
            );
        }
    }

    public function test_get_nonce() {
        $mock_user     = new \WP_User();
        $mock_user->ID = 2;

        $closure = function ( $uid ) {
            return (int) $uid + 1;
        };

        $cases = [
            [
                'hasher'  => new Nonce_Hasher( 'test' ),
                'closure' => null,
                'tick'    => 1,
                'action'  => 'test',
                'token'   => wp_get_session_token(),
                'uid'     => wp_get_current_user()->ID,
            ],
            [
                'hasher'  => new Nonce_Hasher( 'test' ),
                'closure' => null,
                'tick'    => 2,
                'action'  => 'test',
                'token'   => wp_get_session_token(),
                'uid'     => wp_get_current_user()->ID,
            ],
            [
                'hasher'  => new Nonce_Hasher( 'another-test' ),
                'closure' => null,
                'tick'    => 2,
                'action'  => 'another-test',
                'token'   => wp_get_session_token(),
                'uid'     => wp_get_current_user()->ID,
            ],
            [
                'hasher'  => new Nonce_Hasher( 'test' ),
                'closure' => $closure,
                'tick'    => 1,
                'action'  => 'test',
                'token'   => wp_get_session_token(),
                'uid'     => wp_get_current_user()->ID + 1,
            ],
            [
                'hasher'  => new Nonce_Hasher( 'test', 20, $mock_user ),
                'closure' => null,
                'tick'    => 1,
                'action'  => 'test',
                'token'   => wp_get_session_token(),
                'uid'     => $mock_user->ID,
            ],
            [
                'hasher'  => new Nonce_Hasher( 'test', 20, $mock_user ),
                'closure' => null,
                'tick'    => 2,
                'action'  => 'test',
                'token'   => wp_get_session_token(),
                'uid'     => $mock_user->ID,
            ],
            [
                'hasher'  => new Nonce_Hasher( 'test', 20, $mock_user ),
                'closure' => $closure,
                'tick'    => 1,
                'action'  => 'test',
                'token'   => wp_get_session_token(),
                'uid'     => $mock_user->ID,
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case['hasher'] instanceof Nonce_Hasher ) {
                $get_nonce = self::accessible_get_nonce( $case['hasher'] );
                if ( $get_nonce === false ) {
                    $this->fail(
                        'Unable to get a reference to get_nonce() method.'
                    );

                    return;
                }

                if ( ! is_null( $case['closure'] ) ) {
                    add_filter( 'nonce_user_logged_out', $case['closure'] );
                }

                $expected = Nonce_Hasher::hash(
                    $case['tick'] . '|' . $case['action'] . '|' .
                    $case['uid'] . '|' . $case['token']
                );

                $this->assertEquals( $expected, $get_nonce( $case['tick'] ),
                    sprintf( 'Case #%d: Hash result not equal.', $n + 1 )
                );

                if ( ! is_null( $case['closure'] ) ) {
                    remove_filter( 'nonce_user_logged_out', $case['closure'] );
                }
            }
        }
    }

    private static function accessible_get_nonce( $hasher ) {
        try {
            $method = new \ReflectionMethod(
                'Wordpress\Nonce_Hasher', 'get_nonce' );
            $method->setAccessible( true );

            return function ( $tick ) use ( $method, $hasher ) {
                return $method->invokeArgs( $hasher, [ $tick ] );
            };
        } catch ( \ReflectionException $e ) {
            return false;
        }
    }

    public function test_accessors() {
        $mock_user     = new \WP_User();
        $mock_user->ID = 2;
        $mock_token    = 'h324abc4';

        $cases = [
            [
                'hasher'   => new Nonce_Hasher( 'test' ),
                'action'   => 'test',
                'lifetime' => DAY_IN_SECONDS,
                'user'     => wp_get_current_user(),
                'token'    => wp_get_session_token()
            ],
            [
                'hasher'   => new Nonce_Hasher( 'test', 20 ),
                'action'   => 'test',
                'lifetime' => 20,
                'user'     => wp_get_current_user(),
                'token'    => wp_get_session_token()
            ],
            [
                'hasher'   => new Nonce_Hasher( 'test', 20, $mock_user ),
                'action'   => 'test',
                'lifetime' => 20,
                'user'     => $mock_user,
                'token'    => wp_get_session_token()
            ],
            [
                'hasher'   => new Nonce_Hasher( 'test', 20, $mock_user,
                    $mock_token ),
                'action'   => 'test',
                'lifetime' => 20,
                'user'     => $mock_user,
                'token'    => $mock_token
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case['hasher'] instanceof Nonce_Hasher ) {
                $this->assertEquals( $case['lifetime'],
                    $case['hasher']->get_lifetime(),
                    sprintf( 'Case #%d: Lifetime not equal.', $n + 1 )
                );

                $this->assertEquals( $case['action'],
                    $case['hasher']->get_action(),
                    sprintf( 'Case #%d: Action not equal.', $n + 1 )
                );

                $this->assertEquals( $case['user'],
                    $case['hasher']->get_user(),
                    sprintf( 'Case #%d: User not equal.', $n + 1 )
                );

                $this->assertEquals( $case['token'],
                    $case['hasher']->get_token(),
                    sprintf( 'Case #%d: Token not equal.', $n + 1 )
                );
            }
        }
    }

    public function test_tick() {
        $closure = function () {
            return 10;
        };

        $cases = [
            [
                'hasher'   => new Nonce_Hasher( 'test' ),
                'closure'  => null,
                'lifetime' => DAY_IN_SECONDS
            ],
            [
                'hasher'   => new Nonce_Hasher( 'test' ),
                'closure'  => $closure,
                'lifetime' => $closure()
            ],
            [
                'hasher'   => new Nonce_Hasher( 'test', 20 ),
                'closure'  => null,
                'lifetime' => 20
            ],
            [
                'hasher'   => new Nonce_Hasher( 'test', 20 ),
                'closure'  => $closure,
                'lifetime' => $closure()
            ]
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case['hasher'] instanceof Nonce_Hasher ) {
                if ( ! is_null( $case['closure'] ) ) {
                    add_filter( 'nonce_life', $case['closure'] );
                }

                $expected = ceil( time() / ( $case['lifetime'] / 2 ) );
                $this->assertEquals( $expected, $case['hasher']->tick(),
                    sprintf( 'Case #%d: Tick result is not equal.', $n + 1 )
                );

                if ( ! is_null( $case['closure'] ) ) {
                    remove_filter( 'nonce_life', $case['closure'] );
                }
            }
        }
    }
}

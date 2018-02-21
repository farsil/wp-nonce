<?php

namespace Wordpress\Nonce\Test;

use Wordpress\Nonce\NonceGenerator;
use PHPUnit\Framework\TestCase;

class NonceGeneratorTest extends TestCase {
    public function test__construct() {
        $mock_user     = new \stdClass();
        $mock_user->ID = 2;
        $mock_token    = "h324abc4";

        $cases = [
            [
                "generator" => new NonceGenerator( "test" ),
                "action"    => "test",
                "lifetime"  => DAY_IN_SECONDS,
                "user"      => wp_get_current_user(),
                "token"     => wp_get_session_token()
            ],
            [
                "generator" => new NonceGenerator( "test", 20 ),
                "action"    => "test",
                "lifetime"  => 20,
                "user"      => wp_get_current_user(),
                "token"     => wp_get_session_token()
            ],
            [
                "generator" => new NonceGenerator( "test", 20, $mock_user ),
                "action"    => "test",
                "lifetime"  => 20,
                "user"      => $mock_user,
                "token"     => wp_get_session_token()
            ],
            [
                "generator" => new NonceGenerator( "test", 20, $mock_user,
                    $mock_token ),
                "action"    => "test",
                "lifetime"  => 20,
                "user"      => $mock_user,
                "token"     => $mock_token
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case["generator"] instanceof NonceGenerator ) {
                $this->assertAttributeEquals( $case["lifetime"],
                    "lifetime", $case["generator"],
                    sprintf( "Case #%d: Lifetime not equal.", $n + 1 ) );

                $this->assertAttributeEquals( $case["action"],
                    "action", $case["generator"],
                    sprintf( "Case #%d: Action not equal.", $n + 1 ) );

                $this->assertAttributeEquals( $case["user"],
                    "user", $case["generator"],
                    sprintf( "Case #%d: User not equal.", $n + 1 ) );

                $this->assertAttributeEquals( $case["token"],
                    "token", $case["generator"],
                    sprintf( "Case #%d: Token not equal.", $n + 1 ) );
            }
        }
    }

    public function testGenerate() {
        $mock_user     = new \stdClass();
        $mock_user->ID = 2;

        $closure = function ( $uid ) {
            return (int) $uid + 1;
        };

        $cases = [
            [
                "generator" => new NonceGenerator( "test" ),
                "closure"   => null,
                "action"    => 'test',
                "token"     => wp_get_session_token(),
                "uid"       => 0,
            ],
            [
                "generator" => new NonceGenerator( "another-test" ),
                "closure"   => null,
                "action"    => 'another-test',
                "token"     => wp_get_session_token(),
                "uid"       => 0,
            ],
            [
                "generator" => new NonceGenerator( "test" ),
                "closure"   => $closure,
                "action"    => 'test',
                "token"     => wp_get_session_token(),
                "uid"       => 1,
            ],
            [
                "generator" => new NonceGenerator( "test", 20, $mock_user ),
                "closure"   => null,
                "action"    => 'test',
                "token"     => wp_get_session_token(),
                "uid"       => 2,
            ],
            [
                "generator" => new NonceGenerator( "test", 20, $mock_user ),
                "closure"   => $closure,
                "action"    => 'test',
                "token"     => wp_get_session_token(),
                "uid"       => 2,
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case["generator"] instanceof NonceGenerator ) {

                if ( ! is_null( $case["closure"] ) ) {
                    add_filter( "nonce_user_logged_out", $case["closure"] );
                }

                $expected = NonceGenerator::hash(
                    $case['generator']->tick() . '|' . $case['action'] .
                    '|' . $case['uid'] . '|' . $case['token']
                );

                $this->assertEquals( $expected, $case['generator']->generate(),
                    sprintf( "Case #%d: Generate result not equal.",
                        $n + 1 )
                );

                if ( ! is_null( $case["closure"] ) ) {
                    remove_filter( "nonce_user_logged_out",
                        $case["closure"] );
                }
            }
        }
    }

    public function testUrl() {
        $cases = [
            [
                "generator" => new NonceGenerator( "test" ),
                "url"       => 'index.php',
                "name"      => null,
                "prefix"    => 'index.php?_wpnonce=',
            ],
            [
                "generator" => new NonceGenerator( "test" ),
                "url"       => 'index.php?param=1',
                "name"      => null,
                "prefix"    => 'index.php?param=1&amp;_wpnonce=',
            ],
            [
                "generator" => new NonceGenerator( "test" ),
                "url"       => 'index.php',
                "name"      => "foo",
                "prefix"    => 'index.php?foo=',
            ]
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case["generator"] instanceof NonceGenerator ) {

                $expected = $case['prefix'] . $case['generator']->generate();

                if ( is_null( $case['name'] ) ) {
                    $url = $case['generator']->url( $case['url'] );
                } else {
                    $url = $case['generator']->url( $case['url'],
                        $case['name'] );
                }

                $this->assertEquals( $expected, $url,
                    sprintf( "Case #%d: URL not equal.", $n + 1 )
                );
            }
        }
    }

    public function testField() {
        $cases = [
            [
                "generator" => new NonceGenerator( "test" ),
                "name"      => "_wpnonce",
                "referer"   => false,
                "echo"      => false,
                "field_fmt" => '<input type="hidden" id="_wpnonce" name="_wpnonce" value="%s" />',
            ],
            [
                "generator" => new NonceGenerator( "test" ),
                "name"      => "_wpnonce",
                "referer"   => true,
                "echo"      => false,
                "field_fmt" => '<input type="hidden" id="_wpnonce" name="_wpnonce" value="%s" />' .
                               wp_referer_field( false ),
            ],
            [
                "generator" => new NonceGenerator( "test" ),
                "name"      => "_wpnonce",
                "referer"   => false,
                "echo"      => true,
                "field_fmt" => '<input type="hidden" id="_wpnonce" name="_wpnonce" value="%s" />',
            ],
            [
                "generator" => new NonceGenerator( "test" ),
                "name"      => "foo",
                "referer"   => false,
                "echo"      => true,
                "field_fmt" => '<input type="hidden" id="foo" name="foo" value="%s" />',
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case["generator"] instanceof NonceGenerator ) {

                $expected = sprintf(
                    $case['field_fmt'], $case['generator']->generate()
                );

                if ( $case['echo'] === true ) {
                    ob_start();
                }

                $field = $case['generator']->field(
                    $case['name'], $case['referer'], $case['echo']
                );

                if ( $case['echo'] === true ) {
                    $this->assertEquals( $field, ob_get_clean(),
                        sprintf( "Case #%d: Echoed output not equal.",
                            $n + 1 )
                    );
                }

                $this->assertEquals( $expected, $field,
                    sprintf( "Case #%d: Field not equal.", $n + 1 )
                );
            }
        }

    }
}

<?php

use PHPUnit\Framework\TestCase;
use Wordpress\Auth_Exception;

class Auth_Exception_Test extends TestCase {

    public function test__construct() {
        $ex = new Exception();

        $cases = [
            [
                'exception' => new Auth_Exception( 'test' ),
                'action'    => 'test',
                'message'   => '',
                'code'      => 0,
                'previous'  => null
            ],
            [
                'exception' => new Auth_Exception( 'test', 'msg' ),
                'action'    => 'test',
                'message'   => 'msg',
                'code'      => 0,
                'previous'  => null
            ],
            [
                'exception' => new Auth_Exception( 'test', 'msg', 123 ),
                'action'    => 'test',
                'message'   => 'msg',
                'code'      => 123,
                'previous'  => null
            ],
            [
                'exception' => new Auth_Exception( 'test', 'msg', 123, $ex ),
                'action'    => 'test',
                'message'   => 'msg',
                'code'      => 123,
                'previous'  => $ex
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case['exception'] instanceof Auth_Exception ) {

                $this->assertAttributeEquals( $case['action'],
                    'action', $case['exception'],
                    sprintf( 'Case #%d: Action not equal.', $n + 1 )
                );

                $this->assertAttributeEquals( $case['message'],
                    'message', $case['exception'],
                    sprintf( 'Case #%d: Message not equal.', $n + 1 )
                );

                $this->assertAttributeEquals( $case['code'],
                    'code', $case['exception'],
                    sprintf( 'Case #%d: Code not equal.', $n + 1 )
                );

                $this->assertAttributeEquals( $case['previous'],
                    'previous', $case['exception'],
                    sprintf( 'Case #%d: Previous not equal.', $n + 1 )
                );
            }
        }
    }

    public function test_get_action() {
        $cases = [
            [
                'exception' => new Auth_Exception( 'test' ),
                'action'    => 'test',
            ],
            [
                'exception' => new Auth_Exception( 'another-test' ),
                'action'    => 'another-test',
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case['exception'] instanceof Auth_Exception ) {
                $this->assertEquals( $case['action'],
                    $case['exception']->get_action(),
                    sprintf( 'Case #%d: Action not equal.', $n + 1 )
                );
            }
        }
    }
}

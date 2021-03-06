<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: purekitV3_crypto.proto

namespace PurekitV3Crypto;

use Google\Protobuf\Internal\GPBType;
use Google\Protobuf\Internal\RepeatedField;
use Google\Protobuf\Internal\GPBUtil;

/**
 * Generated from protobuf message <code>purekitV3Crypto.EnrollmentRecord</code>
 */
class EnrollmentRecord extends \Google\Protobuf\Internal\Message
{
    /**
     * Generated from protobuf field <code>bytes ns = 1;</code>
     */
    private $ns = '';
    /**
     * Generated from protobuf field <code>bytes nc = 2;</code>
     */
    private $nc = '';
    /**
     * Generated from protobuf field <code>bytes t0 = 3;</code>
     */
    private $t0 = '';
    /**
     * Generated from protobuf field <code>bytes t1 = 4;</code>
     */
    private $t1 = '';

    /**
     * Constructor.
     *
     * @param array $data {
     *     Optional. Data for populating the Message object.
     *
     *     @type string $ns
     *     @type string $nc
     *     @type string $t0
     *     @type string $t1
     * }
     */
    public function __construct($data = NULL) {
        \GPBMetadata\PurekitV3Crypto::initOnce();
        parent::__construct($data);
    }

    /**
     * Generated from protobuf field <code>bytes ns = 1;</code>
     * @return string
     */
    public function getNs()
    {
        return $this->ns;
    }

    /**
     * Generated from protobuf field <code>bytes ns = 1;</code>
     * @param string $var
     * @return $this
     */
    public function setNs($var)
    {
        GPBUtil::checkString($var, False);
        $this->ns = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>bytes nc = 2;</code>
     * @return string
     */
    public function getNc()
    {
        return $this->nc;
    }

    /**
     * Generated from protobuf field <code>bytes nc = 2;</code>
     * @param string $var
     * @return $this
     */
    public function setNc($var)
    {
        GPBUtil::checkString($var, False);
        $this->nc = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>bytes t0 = 3;</code>
     * @return string
     */
    public function getT0()
    {
        return $this->t0;
    }

    /**
     * Generated from protobuf field <code>bytes t0 = 3;</code>
     * @param string $var
     * @return $this
     */
    public function setT0($var)
    {
        GPBUtil::checkString($var, False);
        $this->t0 = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>bytes t1 = 4;</code>
     * @return string
     */
    public function getT1()
    {
        return $this->t1;
    }

    /**
     * Generated from protobuf field <code>bytes t1 = 4;</code>
     * @param string $var
     * @return $this
     */
    public function setT1($var)
    {
        GPBUtil::checkString($var, False);
        $this->t1 = $var;

        return $this;
    }

}


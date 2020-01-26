<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: purekitV3_storage.proto

namespace PurekitV3Storage;

use Google\Protobuf\Internal\GPBType;
use Google\Protobuf\Internal\RepeatedField;
use Google\Protobuf\Internal\GPBUtil;

/**
 * Generated from protobuf message <code>purekitV3Storage.CellKey</code>
 */
class CellKey extends \Google\Protobuf\Internal\Message
{
    /**
     * Generated from protobuf field <code>uint32 version = 1;</code>
     */
    private $version = 0;
    /**
     * Generated from protobuf field <code>bytes cell_key_signed = 2;</code>
     */
    private $cell_key_signed = '';
    /**
     * Generated from protobuf field <code>bytes signature = 3;</code>
     */
    private $signature = '';

    /**
     * Constructor.
     *
     * @param array $data {
     *     Optional. Data for populating the Message object.
     *
     *     @type int $version
     *     @type string $cell_key_signed
     *     @type string $signature
     * }
     */
    public function __construct($data = NULL) {
        \GPBMetadata\PurekitV3Storage::initOnce();
        parent::__construct($data);
    }

    /**
     * Generated from protobuf field <code>uint32 version = 1;</code>
     * @return int
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     * Generated from protobuf field <code>uint32 version = 1;</code>
     * @param int $var
     * @return $this
     */
    public function setVersion($var)
    {
        GPBUtil::checkUint32($var);
        $this->version = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>bytes cell_key_signed = 2;</code>
     * @return string
     */
    public function getCellKeySigned()
    {
        return $this->cell_key_signed;
    }

    /**
     * Generated from protobuf field <code>bytes cell_key_signed = 2;</code>
     * @param string $var
     * @return $this
     */
    public function setCellKeySigned($var)
    {
        GPBUtil::checkString($var, False);
        $this->cell_key_signed = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>bytes signature = 3;</code>
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * Generated from protobuf field <code>bytes signature = 3;</code>
     * @param string $var
     * @return $this
     */
    public function setSignature($var)
    {
        GPBUtil::checkString($var, False);
        $this->signature = $var;

        return $this;
    }

}

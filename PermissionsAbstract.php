<?php

/**
 * PermissionsAbstract.php
 *
 * @author farstrider
 * @version 3 2017-02-26 00:45:12 JST
 */

/**
 * Class PermissionsAbstract
 *
 * The goal here is to provide a relatively simple method for storing/checking permissions when a
 * single entity (e.g. a person) may be assigned multiple permission types.
 *
 * For an interesting explanation on how bit switches work, see:
 * @link http://forums.rpgmakerweb.com/index.php?/topic/13829-working-with-bit-switches/
 */
abstract class PermissionsAbstract {

    /**
     * Contains the bitmask that defines our permissions.
     *
     * @var int
     */
    protected $_bitMask = 0;

    /**
     * Defines the number of "permission flags" we have available for assignment.
     *
     * 32-bit systems can store 2^32 different values, which means we could store up to
     * 4,294,967,295 different flags (2^32 - 1, "-1" representing the sign bit). 64-bit systems
     * would obviously provide a much larger pool of potential flags.
     *
     * For example, if we have ten possible permission levels, we would set $_integerLength to 10
     * (0000000000).  We could then turn specific permissions "on" by assigning a number between
     * one and ten to the bitmask:
     *
     * 0000000010 (1)
     * 0100000000 (8)
     * 0000000001 (10)
     * ..., etc
     *
     * Note that the number ten actually occupies the first available space in this example
     * because we're using a modulus operation when assigning bits.  Otherwise, permission flags
     * could actually overflow the maximum length.  So, in our example, ten would become
     * 10000000000.
     *
     * @var string
     */
    protected $_integerLength;

    /**
     * If the integer given exceeds the maximum supported by the system, we'll use the system max
     * instead.
     *
     * @param string $integerLength
     */
    public function __construct($integerLength = '10')
    {
        if ($integerLength > PHP_INT_MAX) {
            $integerLength = PHP_INT_MAX;
        }

        $this->_integerLength = (string) $integerLength;
    }

    /**
     * Check for the given permission(s).  Multiple permissions can be checked at once by
     * providing multiple arguments.
     *
     * Example:
     * $this->hasPermission('1', '2', '7');
     *
     * @return int
     */
    public function hasPermission()
    {
        $flags = func_get_args();
        $checkMask = 0;

        foreach ($flags as $flag) {
            $checkMask |= 1 << (int) bcmod((string) $flag, $this->_integerLength);
        }

        return $this->_bitMask & $checkMask;
    }

    /**
     * Returns the bitmask representing active permissions as an integer.
     *
     * @return int
     */
    public function getPermissions()
    {
        return (int) $this->_integerLength;
    }

    /**
     * Turns on the given permission in our bitmask using a bitwise OR operation.  We shift the
     * bits in the given flag (integer) one step left so that we have only a single "on" (1) bit
     * in the desired position. In reality, this amounts to simply multiplying by two.
     *
     * @link http://php.net/manual/en/language.operators.bitwise.php
     *
     * @param string $flag
     * @return PermissionsAbstract
     */
    public function setPermission($flag)
    {
        $this->_bitMask |= 1 << (int) bcmod((string) $flag, $this->_integerLength);

        return $this;
    }

    /**
     * Expects a two-dimensional array with integers as the values.
     *
     * @todo Change this to an argument list as in hasPermission()?
     *
     * @param array $permissions
     * @return PermissionsAbstract
     */
    public function setPermissions(array $permissions)
    {
        foreach ($permissions as $flag) {
            $this->setPermission($flag);
        }

        return $this;
    }

    /**
     * Removes the given permission from our bitmask using bitwise AND and NOT operations.  NOT
     * first reverses the bits in the given integer, like so:
     *
     * 0100000000 (8)
     * 1011111111 (~8)
     *
     * "ANDing" ~8 to our bitmask will result in the corresponding bit being turned off (0)
     * because it's currently set to 1 (in theory) in the bitmask.
     *
     * @param string $flag
     * @return PermissionsAbstract
     */
    public function unsetPermission($flag)
    {
        $this->_bitMask &= ~(1 << (int) bcmod((string) $flag, $this->_integerLength));

        return $this;
    }

    /**
     * Expects a two-dimensional array with integers as the values.
     *
     * @param array $permissions
     * @return PermissionsAbstract
     */
    public function unsetPermissions(array $permissions)
    {
        foreach ($permissions as $flag) {
            $this->unsetPermission($flag);
        }

        return $this;
    }
}
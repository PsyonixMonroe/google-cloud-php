<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: google/cloud/retail/v2/search_service.proto

namespace Google\Cloud\Retail\V2\SearchRequest\SpellCorrectionSpec;

use UnexpectedValueException;

/**
 * Enum describing under which mode spell correction should occur.
 *
 * Protobuf type <code>google.cloud.retail.v2.SearchRequest.SpellCorrectionSpec.Mode</code>
 */
class Mode
{
    /**
     * Unspecified spell correction mode. This defaults to
     * [Mode.AUTO][google.cloud.retail.v2.SearchRequest.SpellCorrectionSpec.Mode.AUTO].
     *
     * Generated from protobuf enum <code>MODE_UNSPECIFIED = 0;</code>
     */
    const MODE_UNSPECIFIED = 0;
    /**
     * Google Retail Search will try to find a spell suggestion if there
     * is any and put in the
     * [SearchResponse.corrected_query][google.cloud.retail.v2.SearchResponse.corrected_query].
     * The spell suggestion will not be used as the search query.
     *
     * Generated from protobuf enum <code>SUGGESTION_ONLY = 1;</code>
     */
    const SUGGESTION_ONLY = 1;
    /**
     * Automatic spell correction built by Google Retail Search. Search will
     * be based on the corrected query if found.
     *
     * Generated from protobuf enum <code>AUTO = 2;</code>
     */
    const AUTO = 2;

    private static $valueToName = [
        self::MODE_UNSPECIFIED => 'MODE_UNSPECIFIED',
        self::SUGGESTION_ONLY => 'SUGGESTION_ONLY',
        self::AUTO => 'AUTO',
    ];

    public static function name($value)
    {
        if (!isset(self::$valueToName[$value])) {
            throw new UnexpectedValueException(sprintf(
                    'Enum %s has no name defined for value %s', __CLASS__, $value));
        }
        return self::$valueToName[$value];
    }


    public static function value($name)
    {
        $const = __CLASS__ . '::' . strtoupper($name);
        if (!defined($const)) {
            throw new UnexpectedValueException(sprintf(
                    'Enum %s has no value defined for name %s', __CLASS__, $name));
        }
        return constant($const);
    }
}


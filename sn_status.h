#ifndef _SN_STATUS_H
#define _SN_STATUS_H
/**
 * @file sn_status.h
 * @defgroup sn_status StarfishNet Status (Return) Codes
 * @{
 */
/******************************************************************************
 * Based on aj_status.h from the AllJoyn thin client.
 *
 * Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

/**
 * Status codes
 */
typedef enum {
    SN_OK               , /**< Success status */
    SN_ERR_NULL         , /**< Unexpected NULL pointer */
    SN_ERR_UNEXPECTED   , /**< An operation was unexpected at this time */
    SN_ERR_INVALID      , /**< A value was invalid */
    SN_ERR_RADIO        , /**< An error while communicating with the radio */
    SN_ERR_TIMEOUT      , /**< A timeout occurred */
    SN_ERR_END_OF_DATA  , /**< Not enough data */
    SN_ERR_RESOURCES    , /**< Insufficient memory to perform the operation */
    SN_ERR_SECURITY     , /**< Authentication or decryption failed */
    SN_ERR_CONNECT      , /**< Network connect failed */
    SN_ERR_UNKNOWN      , /**< A unknown value */
    SN_ERR_NO_MATCH     , /**< Something didn't match */
    SN_ERR_SIGNATURE    , /**< Signature is not what was expected */
    SN_ERR_DISALLOWED   , /**< An operation was not allowed */
    SN_ERR_FAILURE      , /**< A failure has occurred */
    SN_ERR_RESTART      , /**< The OEM event loop must restart */
    SN_ERR_LINK_TIMEOUT , /**< The bus link is inactive too long */
    SN_ERR_DRIVER       , /**< An error communicating with a lower-layer driver */
    SN_ERR_OBJECT_PATH  , /**< Object path was not specified */
    SN_ERR_BUSY         , /**< An operation failed and should be retried later */
    SN_ERR_DHCP         , /**< A DHCP operation has failed */
    SN_ERR_ACCESS       , /**< The operation specified is not allowed */
    SN_ERR_SESSION_LOST , /**< The session was lost */
    SN_ERR_LINK_DEAD    , /**< The network link is now dead */
    SN_ERR_HDR_CORRUPT  , /**< The message header was corrupt */
    SN_ERR_RESTART_APP  , /**< The application must cleanup and restart */
    SN_ERR_INTERRUPTED  , /**< An I/O operation (READ) was interrupted */
    SN_ERR_REJECTED     , /**< The connection was rejected */
    SN_ERR_RANGE        , /**< Value provided was out of range */
    SN_ERR_ACCESS_ROUTING_NODE, /**< Access defined by routing node */
    SN_ERR_KEY_EXPIRED  , /**< The key has expired */
    SN_ERR_SPI_NO_SPACE , /**< Out of space error */
    SN_ERR_SPI_READ     , /**< Read error */
    SN_ERR_SPI_WRITE    , /**< Write error */
    SN_ERR_OLD_VERSION  , /**< Router you connected to is old and unsupported */

    SN_ERR_ERROR_END      /**< The last error status code */

} SN_Status;

/**
 * @}
 */
#endif

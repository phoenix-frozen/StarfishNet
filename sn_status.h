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

    SN_OK               = 0,  /**< Success status */
    SN_ERR_NULL         = 1,  /**< Unexpected NULL pointer */
    SN_ERR_UNEXPECTED   = 2,  /**< An operation was unexpected at this time */
    SN_ERR_INVALID      = 3,  /**< A value was invalid */
    SN_ERR_IO_BUFFER    = 4,  /**< An I/O buffer was invalid or in the wrong state */
    SN_ERR_READ         = 5,  /**< An error while reading data from the network */
    SN_ERR_WRITE        = 6,  /**< An error while writing data to the network */
    SN_ERR_TIMEOUT      = 7,  /**< A timeout occurred */
    SN_ERR_MARSHAL      = 8,  /**< Marshaling failed due to badly constructed message argument */
    SN_ERR_UNMARSHAL    = 9,  /**< Unmarshaling failed due to a corrupt or invalid message */
    SN_ERR_END_OF_DATA  = 10, /**< Not enough data */
    SN_ERR_RESOURCES    = 11, /**< Insufficient memory to perform the operation */
    SN_ERR_NO_MORE      = 12, /**< Attempt to unmarshal off the end of an array */
    SN_ERR_SECURITY     = 13, /**< Authentication or decryption failed */
    SN_ERR_CONNECT      = 14, /**< Network connect failed */
    SN_ERR_UNKNOWN      = 15, /**< A unknown value */
    SN_ERR_NO_MATCH     = 16, /**< Something didn't match */
    SN_ERR_SIGNATURE    = 17, /**< Signature is not what was expected */
    SN_ERR_DISALLOWED   = 18, /**< An operation was not allowed */
    SN_ERR_FAILURE      = 19, /**< A failure has occurred */
    SN_ERR_RESTART      = 20, /**< The OEM event loop must restart */
    SN_ERR_LINK_TIMEOUT = 21, /**< The bus link is inactive too long */
    SN_ERR_DRIVER       = 22, /**< An error communicating with a lower-layer driver */
    SN_ERR_OBJECT_PATH  = 23, /**< Object path was not specified */
    SN_ERR_BUSY         = 24, /**< An operation failed and should be retried later */
    SN_ERR_DHCP         = 25, /**< A DHCP operation has failed */
    SN_ERR_ACCESS       = 26, /**< The operation specified is not allowed */
    SN_ERR_SESSION_LOST = 27, /**< The session was lost */
    SN_ERR_LINK_DEAD    = 28, /**< The network link is now dead */
    SN_ERR_HDR_CORRUPT  = 29, /**< The message header was corrupt */
    SN_ERR_RESTART_APP  = 30, /**< The application must cleanup and restart */
    SN_ERR_INTERRUPTED  = 31, /**< An I/O operation (READ) was interrupted */
    SN_ERR_REJECTED     = 32, /**< The connection was rejected */
    SN_ERR_RANGE        = 33, /**< Value provided was out of range */
    SN_ERR_ACCESS_ROUTING_NODE = 34, /**< Access defined by routing node */
    SN_ERR_KEY_EXPIRED  = 35, /**< The key has expired */
    SN_ERR_SPI_NO_SPACE = 36, /**< Out of space error */
    SN_ERR_SPI_READ     = 37, /**< Read error */
    SN_ERR_SPI_WRITE    = 38, /**< Write error */
    SN_ERR_OLD_VERSION  = 39, /**< Router you connected to is old and unsupported */

    SN_STATUS_LAST      = 39  /**< The last error status code */

} SN_Status;

/**
 * @}
 */
#endif

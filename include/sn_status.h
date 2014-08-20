#ifndef __SN_STATUS_H__
#define __SN_STATUS_H__
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
    SN_ERR_UNIMPLEMENTED, /**< An operation has not yet been implemented */
    SN_ERR_INVALID      , /**< A value was invalid */
    SN_ERR_UNKNOWN      , /**< A unknown value */
    SN_ERR_RADIO        , /**< An error while communicating with the radio */
    SN_ERR_TIMEOUT      , /**< A timeout occurred */
    SN_ERR_END_OF_DATA  , /**< Not enough data */
    SN_ERR_RESOURCES    , /**< Insufficient memory to perform the operation */
    SN_ERR_SECURITY     , /**< Authentication or decryption failed */
    SN_ERR_SIGNATURE    , /**< Signature verification failed */
    SN_ERR_KEYGEN       , /**< Key generation failed */
    SN_ERR_DISALLOWED   , /**< An operation was not allowed */
    SN_ERR_OLD_VERSION  , /**< Router you connected to is old and unsupported */
    SN_ERR_BUSY         , /**< An operation failed and should be retried later */

    SN_ERR_ERROR_END      /**< The last error status code + 1*/
} SN_Status;

/**
 * @}
 */
#endif /* __SN_STATUS_H__ */

#ifndef __SN_STATUS_H__
#define __SN_STATUS_H__

typedef enum {
    SN_OK               , //Success
    SN_ERR_NULL         , //Unexpected NULL pointer
    SN_ERR_UNEXPECTED   , //Operation was unexpected at this time
    SN_ERR_UNIMPLEMENTED, //Operation has not been implemented
    SN_ERR_INVALID      , //Argument or operand was invalid
    SN_ERR_UNKNOWN      , //Lookup failure
    SN_ERR_RADIO        , //An error while communicating with the radio
    SN_ERR_END_OF_DATA  , //Packet size mismatch
    SN_ERR_RESOURCES    , //Resource allocation failure
    SN_ERR_SECURITY     , //Authentication or decryption failed
    SN_ERR_SIGNATURE    , //Signature verification failed
    SN_ERR_KEYGEN       , //Key generation failed
    SN_ERR_OLD_VERSION  , //Router you connected to is old and unsupported
    SN_ERR_DISCONNECTED , //Contact was lost with the remote node
} SN_Status;

#endif /* __SN_STATUS_H__ */

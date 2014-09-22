#ifndef __SN_TXRX_H__
#define __SN_TXRX_H__

//StarfishNet packet header
typedef struct __attribute__((packed)) network_header {
    struct __attribute__((packed)) {
        uint8_t protocol_id;
        uint8_t protocol_ver;
        uint16_t src_addr;
        uint16_t dst_addr;
        union {
            struct {
                uint8_t encrypt :1;
                uint8_t         :7;
            };
            uint8_t attributes;
        };
    } data;

    struct __attribute__((packed)) {
        uint16_t counter;
        uint8_t  tag[SN_Tag_size];
    } crypto;
} network_header_t;

#endif /* __SN_TXRX_H__ */

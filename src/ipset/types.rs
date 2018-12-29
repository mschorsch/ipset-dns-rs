#![allow(dead_code)]

//
// IPSET
// see /usr/include/linux/netfilter/ipset/ip_set.h
//

/* The protocol versions */
pub const IPSET_PROTOCOL: u8 = 6;

/* The max length of strings including NUL: set and type identifiers */
pub const IPSET_MAXNAMELEN: usize = 32;

/* Message types and commands */
pub const IPSET_CMD_ADD: u16 = 9;        /* 9: Add an element to a set */

/* Attributes at command level */
pub const IPSET_ATTR_UNSPEC: u16 = 0;
pub const IPSET_ATTR_PROTOCOL: u16 = 1;    /* 1: Protocol version */
pub const IPSET_ATTR_SETNAME: u16 = 2;     /* 2: Name of the set */
pub const IPSET_ATTR_TYPENAME: u16 = 3;    /* 3: Typename */
pub const IPSET_ATTR_SETNAME2: u16 = IPSET_ATTR_TYPENAME;  /* Setname at rename/swap */
pub const IPSET_ATTR_REVISION: u16 = 4;    /* 4: Settype revision */
pub const IPSET_ATTR_FAMILY: u16 = 5;    /* 5: Settype family */
pub const IPSET_ATTR_FLAGS: u16 = 6;    /* 6: Flags at command level */
pub const IPSET_ATTR_DATA: u16 = 7;    /* 7: Nested attributes */
pub const IPSET_ATTR_ADT: u16 = 8;        /* 8: Multiple data containers */
pub const IPSET_ATTR_LINENO: u16 = 9;    /* 9: Restore lineno */
pub const IPSET_ATTR_PROTOCOL_MIN: u16 = 10;  /* 10: Minimal supported version number */
pub const IPSET_ATTR_REVISION_MIN: u16 = IPSET_ATTR_PROTOCOL_MIN;  /* type rev min */
pub const IPSET_ATTR_INDEX: u16 = 11;    /* 11: Kernel index of set */

/* CADT specific attributes */
pub const IPSET_ATTR_IP: u16 = IPSET_ATTR_UNSPEC + 1;

/* IP specific attributes */
pub const IPSET_ATTR_IPADDR_IPV4: u16 = IPSET_ATTR_UNSPEC + 1;
pub const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

/* SPDX-License-Identifier: Apache-2.0
 * Canonical numeric TC handles. tc's textual components are HEXADECIMAL.
 * build.rs generates the Rust constants from these literal definitions.
 */
#ifndef NETQMON_CLASSID_H
#define NETQMON_CLASSID_H
#define NETQMON_QOS_DOWNLOAD_MAJOR 0x0051
#define NETQMON_QOS_UPLOAD_MAJOR 0x0052
#define NETQMON_QOS_ROOT_MINOR 0x0001
#define NETQMON_QOS_BYPASS_MINOR 0xfffe
#define NETQMON_QOS_CLIENT_FIRST 0x0100
#define NETQMON_QOS_CLIENT_LAST 0x01ff
#define NETQMON_QOS_DEFAULT_FIRST 0x0200
#define NETQMON_QOS_DEFAULT_LAST 0x02ff
#define NETQMON_QOS_APPLICATION_FIRST 0x1000
#define NETQMON_QOS_APPLICATION_LAST 0x1fff
#define NETQMON_QOS_APPLICATIONS_PER_CLIENT 0x0010
#define NETQMON_QOS_POC_CLIENT_MINOR 0x0100
#define NETQMON_QOS_POC_LEAF_MINOR 0x0200
#define NETQMON_QOS_POC_ABI_VERSION 0x0002
#define NETQMON_QOS_CLASSID(major, minor) (((major) << 16) | (minor))
#endif

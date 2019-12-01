/* Copyright (c) 2013-2019 GomSpace A/S. All rights reserved. */
#ifndef GS_CSP_EXTERNAL_CSP_DEBUG_H
#define GS_CSP_EXTERNAL_CSP_DEBUG_H

/**
   Hook into GomSpace log system.

   Not part of standard libcsp.
*/

#include <gs/util/log/log.h>

#ifdef __cplusplus
extern "C" {
#endif

GS_LOG_GROUP_EXTERN(gs_csp_log);

#define csp_log_error(...)     log_error_group(gs_csp_log, ##__VA_ARGS__)
#define csp_log_warn(...)      log_warning_group(gs_csp_log, ##__VA_ARGS__)
#define csp_log_info(...)      log_info_group(gs_csp_log, ##__VA_ARGS__)

#define csp_log_packet(...)    log_info_group(gs_csp_log, ##__VA_ARGS__)
#define csp_log_buffer(...)    log_trace_group(gs_csp_log, ##__VA_ARGS__)
#define csp_log_protocol(...)  log_debug_group(gs_csp_log, ##__VA_ARGS__)
#define csp_log_lock(...)      log_trace_group(gs_csp_log, ##__VA_ARGS__)

#define csp_debug_toggle_level(...)  {}
#define csp_debug_set_level(...)     {}
#define csp_debug_get_level(...)     {}
    
#ifdef __cplusplus
}
#endif
#endif

#include "nanodns.h"
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <ps5/klog.h>

int g_debug_enabled = 1;
static FILE *g_log_file = NULL;

static void log_emit_direct(const char *buf, int to_debug) {
  if(g_log_file != NULL) {
    fputs(buf, g_log_file);
    fflush(g_log_file);
  }
  if(to_debug) {
    fputs(buf, stdout);
    fflush(stdout);
    klog_puts(buf);
  }
}

int logger_init(const app_config_t *cfg) {
  char buf[512];

  if(g_log_file != NULL) {
    fclose(g_log_file);
    g_log_file = NULL;
  }

  g_debug_enabled = cfg->debug_enabled ? 1 : 0;
  g_log_file = fopen(cfg->log_path, "a");
  if(g_log_file == NULL) {
    if(!g_debug_enabled) g_debug_enabled = 1;
    snprintf(buf, sizeof(buf), "[nanodns] failed to open log file %s: %s\n",
             cfg->log_path, strerror(errno));
    log_emit_direct(buf, g_debug_enabled);
    return -1;
  }

  setvbuf(g_log_file, NULL, _IOLBF, 0);
  return 0;
}

void logger_fini(void) {
  if(g_log_file != NULL) {
    fclose(g_log_file);
    g_log_file = NULL;
  }
}

void log_printf(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  int written;

  va_start(ap, fmt);
  written = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if(written < 0) return;
  log_emit_direct(buf, g_debug_enabled);
}

void log_errno(const char *what) {
  log_printf("[nanodns] %s: %s\n", what, strerror(errno));
}

void normalize_domain(const char *input, char *output, size_t output_size) {
  size_t out = 0;
  if(output_size == 0) return;
  for(; *input != '\0' && out + 1 < output_size; ++input) {
    output[out++] = (char)tolower((unsigned char)*input);
  }
  while(out > 0 && output[out - 1] == '.') --out;
  output[out] = '\0';
}


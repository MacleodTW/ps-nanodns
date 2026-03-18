#include "nanodns.h"
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>

typedef struct {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
  size_t qname_offset;
  size_t question_end;
  char qname[MAX_DOMAIN_LEN];
  uint16_t qtype;
  uint16_t qclass;
} dns_question_t;

static const char *dns_type_to_string(uint16_t qtype) {
  switch(qtype) {
  case 1: return "A";
  case 2: return "NS";
  case 5: return "CNAME";
  case 6: return "SOA";
  case 12: return "PTR";
  case 15: return "MX";
  case 16: return "TXT";
  case 28: return "AAAA";
  case 33: return "SRV";
  case 41: return "OPT";
  case 255: return "ANY";
  default: return "OTHER";
  }
}

static const char *dns_rcode_to_string(uint16_t rcode) {
  switch(rcode) {
  case 0: return "NOERROR";
  case 1: return "FORMERR";
  case 2: return "SERVFAIL";
  case 3: return "NXDOMAIN";
  case 4: return "NOTIMP";
  case 5: return "REFUSED";
  default: return "OTHER";
  }
}

static uint16_t read_u16(const uint8_t *ptr) {
  return (uint16_t)(((uint16_t)ptr[0] << 8) | ptr[1]);
}

static uint32_t read_u32(const uint8_t *ptr) {
  return ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) |
         ((uint32_t)ptr[2] << 8) | ptr[3];
}

static void write_u16(uint8_t *ptr, uint16_t value) {
  ptr[0] = (uint8_t)((value >> 8) & 0xff);
  ptr[1] = (uint8_t)(value & 0xff);
}

static void write_u32(uint8_t *ptr, uint32_t value) {
  ptr[0] = (uint8_t)((value >> 24) & 0xff);
  ptr[1] = (uint8_t)((value >> 16) & 0xff);
  ptr[2] = (uint8_t)((value >> 8) & 0xff);
  ptr[3] = (uint8_t)(value & 0xff);
}

static int64_t now_ms(void) {
  struct timeval tv;
  if(gettimeofday(&tv, NULL) != 0) return 0;
  return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int dns_expand_name(const uint8_t *packet, size_t packet_len, size_t *offset,
                           char *output, size_t output_len) {
  size_t cursor = *offset;
  size_t end_offset = (size_t)-1;
  size_t out = 0;
  int jumps = 0;

  if(output_len == 0) return -1;

  while(cursor < packet_len) {
    uint8_t len = packet[cursor];
    if((len & 0xc0) == 0xc0) {
      uint16_t ptr;
      if(cursor + 1 >= packet_len) return -1;
      ptr = (uint16_t)(((len & 0x3f) << 8) | packet[cursor + 1]);
      if(ptr >= packet_len || ++jumps > 16) return -1;
      if(end_offset == (size_t)-1) end_offset = cursor + 2;
      cursor = ptr;
      continue;
    }
    if((len & 0xc0) != 0) return -1;
    ++cursor;
    if(len == 0) {
      output[out] = '\0';
      *offset = end_offset == (size_t)-1 ? cursor : end_offset;
      return 0;
    }
    if(cursor + len > packet_len) return -1;
    if(out != 0) {
      if(out + 1 >= output_len) return -1;
      output[out++] = '.';
    }
    if(out + len >= output_len) return -1;
    memcpy(&output[out], &packet[cursor], len);
    out += len;
    cursor += len;
  }
  return -1;
}

static int dns_parse_question(const uint8_t *packet, size_t packet_len, dns_question_t *q) {
  size_t offset = 12;
  char normalized[MAX_DOMAIN_LEN];

  if(packet_len < 12) return -1;
  memset(q, 0, sizeof(*q));
  q->id = read_u16(&packet[0]);
  q->flags = read_u16(&packet[2]);
  q->qdcount = read_u16(&packet[4]);
  q->ancount = read_u16(&packet[6]);
  q->nscount = read_u16(&packet[8]);
  q->arcount = read_u16(&packet[10]);
  q->qname_offset = offset;

  if(q->qdcount == 0) return -1;
  if(dns_expand_name(packet, packet_len, &offset, q->qname, sizeof(q->qname)) != 0) return -1;
  if(offset + 4 > packet_len) return -1;

  q->qtype = read_u16(&packet[offset]);
  q->qclass = read_u16(&packet[offset + 2]);
  q->question_end = offset + 4;

  normalize_domain(q->qname, normalized, sizeof(normalized));
  snprintf(q->qname, sizeof(q->qname), "%s", normalized);
  return 0;
}

static int build_error_response(const uint8_t *request, size_t request_len,
                                const dns_question_t *question, uint16_t rcode,
                                uint8_t *response, size_t response_cap, size_t *response_len) {
  size_t question_len;
  if(response_cap < question->question_end) return -1;
  question_len = question->question_end - 12;
  memcpy(response, request, question->question_end);
  write_u16(&response[2], (uint16_t)(0x8000 | (question->flags & 0x0100) | 0x0080 | (rcode & 0x000f)));
  write_u16(&response[4], 1);
  write_u16(&response[6], 0);
  write_u16(&response[8], 0);
  write_u16(&response[10], 0);
  *response_len = 12 + question_len;
  (void)request_len;
  return 0;
}

static int build_nodata_response(const uint8_t *request, size_t request_len,
                                 const dns_question_t *question, uint8_t *response,
                                 size_t response_cap, size_t *response_len) {
  return build_error_response(request, request_len, question, 0, response, response_cap, response_len);
}

static int build_override_response(const uint8_t *request, const dns_question_t *question,
                                   const struct in_addr *addr, uint8_t *response,
                                   size_t response_cap, size_t *response_len) {
  size_t question_len = question->question_end - 12;
  size_t offset;

  if(response_cap < question->question_end + 16) return -1;
  memcpy(response, request, question->question_end);
  write_u16(&response[2], (uint16_t)(0x8000 | (question->flags & 0x0100) | 0x0080));
  write_u16(&response[4], 1);
  write_u16(&response[6], 1);
  write_u16(&response[8], 0);
  write_u16(&response[10], 0);

  offset = 12 + question_len;
  write_u16(&response[offset], 0xc00c); offset += 2;
  write_u16(&response[offset], 1); offset += 2;
  write_u16(&response[offset], 1); offset += 2;
  write_u32(&response[offset], OVERRIDE_TTL); offset += 4;
  write_u16(&response[offset], 4); offset += 2;
  memcpy(&response[offset], &addr->s_addr, 4); offset += 4;
  *response_len = offset;
  return 0;
}

static void log_dns_query(const dns_question_t *question, const struct sockaddr_in *client) {
  char client_ip[INET_ADDRSTRLEN];
  if(inet_ntop(AF_INET, &client->sin_addr, client_ip, sizeof(client_ip)) == NULL) {
    snprintf(client_ip, sizeof(client_ip), "<invalid>");
  }
  log_printf("[nanodns] query from=%s:%u id=0x%04x qname=%s qtype=%s(%u) qclass=%u\n",
             client_ip, ntohs(client->sin_port), question->id,
             question->qname[0] ? question->qname : ".", dns_type_to_string(question->qtype),
             question->qtype, question->qclass);
}

static void log_answer_record(const uint8_t *packet, size_t packet_len, size_t *offset, size_t index) {
  char name[MAX_DOMAIN_LEN], ipbuf[INET6_ADDRSTRLEN];
  uint16_t type, klass, rdlength;
  uint32_t ttl;
  size_t rdata_offset;

  if(dns_expand_name(packet, packet_len, offset, name, sizeof(name)) != 0 || *offset + 10 > packet_len) {
    *offset = packet_len;
    return;
  }
  type = read_u16(&packet[*offset]);
  klass = read_u16(&packet[*offset + 2]);
  ttl = read_u32(&packet[*offset + 4]);
  rdlength = read_u16(&packet[*offset + 8]);
  *offset += 10;

  if(*offset + rdlength > packet_len) {
    *offset = packet_len;
    return;
  }
  rdata_offset = *offset;

  if(type == 1 && rdlength == 4 && inet_ntop(AF_INET, &packet[rdata_offset], ipbuf, sizeof(ipbuf)) != NULL) {
    log_printf("[nanodns]   answer[%zu] name=%s type=A ttl=%u class=%u data=%s\n", index, name[0] ? name : ".", ttl, klass, ipbuf);
  } else if(type == 28 && rdlength == 16 && inet_ntop(AF_INET6, &packet[rdata_offset], ipbuf, sizeof(ipbuf)) != NULL) {
    log_printf("[nanodns]   answer[%zu] name=%s type=AAAA ttl=%u class=%u data=%s\n", index, name[0] ? name : ".", ttl, klass, ipbuf);
  } else {
    log_printf("[nanodns]   answer[%zu] name=%s type=%s ttl=%u class=%u\n", index, name[0] ? name : ".", dns_type_to_string(type), ttl, klass);
  }
  *offset += rdlength;
}

static void log_dns_response(const uint8_t *packet, size_t packet_len, const char *via) {
  dns_question_t question;
  uint16_t flags, rcode;
  size_t offset;

  if(dns_parse_question(packet, packet_len, &question) != 0) return;
  flags = read_u16(&packet[2]);
  rcode = (uint16_t)(flags & 0x000f);
  log_printf("[nanodns] response via=%s id=0x%04x qname=%s qtype=%s(%u) rcode=%s(%u)\n",
             via, question.id, question.qname[0] ? question.qname : ".",
             dns_type_to_string(question.qtype), question.qtype, dns_rcode_to_string(rcode), rcode);
  offset = question.question_end;
  for(size_t i = 0; i < question.ancount && offset < packet_len; ++i) {
    log_answer_record(packet, packet_len, &offset, i);
  }
}

// Updated forward_query to receive upstreams directly to avoid global config lock
static int forward_query_to_upstream(const upstream_t *upstreams, size_t upstream_count, int timeout_ms, 
                                     const uint8_t *request, size_t request_len, uint16_t request_id,
                                     uint8_t *response, size_t response_cap,
                                     size_t *response_len, char *via, size_t via_len) {
  struct { int fd; const upstream_t *upstream; } active[MAX_UPSTREAMS];
  struct pollfd pfds[MAX_UPSTREAMS];
  size_t active_count = 0;
  int64_t deadline_ms = now_ms() + timeout_ms;

  for(size_t i = 0; i < upstream_count; ++i) {
    struct sockaddr_in upstream_addr;
    int fd;
    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(DNS_PORT);
    upstream_addr.sin_addr = upstreams[i].addr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) continue;
    if(connect(fd, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) != 0 ||
       send(fd, request, request_len, 0) < 0) {
      close(fd);
      continue;
    }
    active[active_count].fd = fd;
    active[active_count].upstream = &upstreams[i];
    pfds[active_count].fd = fd;
    pfds[active_count].events = POLLIN;
    pfds[active_count].revents = 0;
    ++active_count;
  }

  if(active_count == 0) return -1;

  while(active_count > 0) {
    int64_t remaining_ms = deadline_ms - now_ms();
    if(remaining_ms < 0) remaining_ms = 0;
    if(poll(pfds, active_count, (int)remaining_ms) <= 0) break;

    for(size_t idx = 0; idx < active_count; ++idx) {
      if(pfds[idx].revents & POLLIN) {
        ssize_t nread = recv(active[idx].fd, response, response_cap, 0);
        if(nread >= 12 && read_u16(response) == request_id) {
          *response_len = (size_t)nread;
          snprintf(via, via_len, "%s", active[idx].upstream->text);
          for(size_t j = 0; j < active_count; ++j) close(active[j].fd);
          return 0;
        }
      }
    }
    break;
  }
  for(size_t i = 0; i < active_count; ++i) close(active[i].fd);
  return -1;
}

void dns_process_request(int server_fd, const app_config_t *cfg) {
  uint8_t request[MAX_DNS_PACKET];
  uint8_t response[MAX_DNS_PACKET];
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  dns_question_t question;
  ssize_t received;

  received = recvfrom(server_fd, request, sizeof(request), 0,
                      (struct sockaddr *)&client_addr, &client_len);
  if(received < 0) {
    log_errno("recvfrom(client)");
    return;
  }

  if(dns_parse_question(request, (size_t)received, &question) != 0) return;
  log_dns_query(&question, &client_addr);

  // 1. Acquire read lock before matching rules
  pthread_rwlock_rdlock(&g_cfg_lock);

  const override_rule_t *rule = NULL;
  if(!has_matching_exception(cfg, question.qname)) {
    rule = find_matching_rule(cfg, question.qname);
  }

  // 2. Safely copy data needed for downstream network operations
  struct in_addr target_ip;
  int is_override = 0;
  if(rule != NULL) {
    target_ip = rule->addr;
    is_override = 1;
  }

  upstream_t local_upstreams[MAX_UPSTREAMS];
  size_t local_upstream_count = cfg->upstream_count;
  int local_timeout = cfg->timeout_ms;
  for(size_t i = 0; i < local_upstream_count; ++i) {
    local_upstreams[i] = cfg->upstreams[i];
  }

  // 3. Release read lock immediately after copying
  pthread_rwlock_unlock(&g_cfg_lock);

  if(question.qdcount == 1 && question.qclass == 1 && is_override) {
    size_t response_len;
    int build_rc;
    const char *response_via;
    if(question.qtype == 1 || question.qtype == 255) {
      build_rc = build_override_response(request, &question, &target_ip,
                                         response, sizeof(response), &response_len);
      response_via = "override";
    } else {
      build_rc = build_nodata_response(request, (size_t)received, &question,
                                       response, sizeof(response), &response_len);
      response_via = "override-nodata";
    }
    if(build_rc == 0) {
      if(sendto(server_fd, response, response_len, 0, (struct sockaddr *)&client_addr, client_len) >= 0) {
        log_dns_response(response, response_len, response_via);
      }
      return;
    }
  }

  {
    size_t response_len = 0;
    char via[INET_ADDRSTRLEN];
    // Use local copies for upstream requests to prevent locking
    if(forward_query_to_upstream(local_upstreams, local_upstream_count, local_timeout, 
                                 request, (size_t)received, question.id,
                                 response, sizeof(response), &response_len, via, sizeof(via)) == 0) {
      if(sendto(server_fd, response, response_len, 0, (struct sockaddr *)&client_addr, client_len) >= 0) {
        log_dns_response(response, response_len, via);
      }
    } else {
      if(build_error_response(request, (size_t)received, &question, 2, response, sizeof(response), &response_len) == 0) {
        sendto(server_fd, response, response_len, 0, (struct sockaddr *)&client_addr, client_len);
      }
    }
  }
}


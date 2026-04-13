#pragma once
#include "config.h"
#include <stdbool.h>
#include <stdint.h>

void bogon_cfg_apply (const Cfg *cfg);
bool bogon_ip_match (const uint8_t ip[16]);
bool bogon_rule_parse (const char *s, BogonRule *out);

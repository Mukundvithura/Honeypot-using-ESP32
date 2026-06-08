#ifndef DFA_H
#define DFA_H

#include <Arduino.h>

enum DfaState {
  S_IDLE    = 0,
  S_RECON   = 1,
  S_PRIVESC = 2,
  S_EXFIL   = 3,
  S_LATERAL = 4,
  S_PERSIST = 5,
  S_MALWARE = 6,
  S_ALERT   = 7,
  DFA_NUM_STATES
};

enum DfaInput {
  IN_RECON   = 0,
  IN_PRIVESC = 1,
  IN_EXFIL   = 2,
  IN_LATERAL = 3,
  IN_PERSIST = 4,
  IN_MALWARE = 5,
  IN_OTHER   = 6,
  DFA_NUM_INPUTS
};

struct DfaCtx {
  DfaState state      = S_IDLE;
  uint32_t cmdCount   = 0;
  uint32_t alertCount = 0;
};

extern const char* STATE_NAME[DFA_NUM_STATES];
extern const char* INPUT_NAME[DFA_NUM_INPUTS];

extern const DfaState DFA_TABLE[DFA_NUM_STATES][DFA_NUM_INPUTS];

DfaInput dfaClassify(const String& cmd);
DfaState dfaFeed(DfaCtx& ctx, const String& ip, uint16_t port, const String& cmd);

#endif

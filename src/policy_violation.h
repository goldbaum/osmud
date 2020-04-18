#ifndef _POLICY_VIOLATION
#define _POLICY_VIOLATION

#define SYSLOG_ACTION_READ 2


bool policy_violation_init(void);
void policy_violation_free(void);

#endif /* _POLICY_VIOLATION */
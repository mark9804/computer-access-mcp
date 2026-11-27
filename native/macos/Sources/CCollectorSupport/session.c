#include "CCollectorSupport.h"
#include <bsm/audit.h>
#include <unistd.h>
int collector_audit_session(uint32_t *session) {
    if (!session) return -1;
    auditinfo_addr_t info = {0};
    if (getaudit_addr(&info, sizeof(info)) != 0 || info.ai_asid < 0 || info.ai_asid == (au_asid_t)-1) return -1;
    *session = (uint32_t)info.ai_asid;
    return 0;
}

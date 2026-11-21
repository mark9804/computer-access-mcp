#ifndef C_COLLECTOR_SUPPORT_H
#define C_COLLECTOR_SUPPORT_H
#include <stdint.h>

int collector_audit_session(uint32_t *session);

typedef struct collector_progress_page collector_progress_page;
typedef struct collector_progress_snapshot {
    int64_t request_id, read_id, operation, api, attribute, phase;
    int64_t started_ms, updated_ms, deadline_ms, status, index;
} collector_progress_snapshot;

collector_progress_page *collector_progress_create(int *fd);
collector_progress_page *collector_progress_attach(int fd);
void collector_progress_unmap(collector_progress_page *page);
int collector_progress_write(collector_progress_page *page, const collector_progress_snapshot *snapshot);
int collector_progress_read(const collector_progress_page *page, collector_progress_snapshot *snapshot);

// Atomic fence marking that the worker is inside the initial focus AX query.
void collector_focus_fence_set(collector_progress_page *page, int64_t deadline_ms);
int collector_focus_fence_matches(const collector_progress_page *page, int64_t deadline_ms);

int collector_pipe_known_empty(int fd);
#endif

#include "CCollectorSupport.h"
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define PROGRESS_MAGIC UINT64_C(0x4453485052473031)
#define PROGRESS_VERSION UINT64_C(2)
#define PROGRESS_FIELDS 11

_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2 && ATOMIC_LONG_LOCK_FREE == 2,
               "progress page requires lock-free 64-bit atomics");

struct progress_slot {
    _Atomic uint64_t sequence;
    _Atomic uint64_t fields[PROGRESS_FIELDS];
};

struct collector_progress_page {
    uint64_t magic, version, mapped_size;
    _Atomic uint64_t committed;
    _Atomic uint64_t focus_deadline;
    struct progress_slot slots[2];
};

_Static_assert(sizeof(struct collector_progress_page) <= 4096, "progress page must fit one page");

static int valid_page(const collector_progress_page *page) {
    return page && page->magic == PROGRESS_MAGIC && page->version == PROGRESS_VERSION &&
        page->mapped_size >= sizeof(*page) && page->mapped_size <= 65536 &&
        atomic_is_lock_free(&page->committed) && atomic_is_lock_free(&page->slots[0].sequence) &&
        atomic_is_lock_free(&page->slots[0].fields[0]);
}

static int valid_fd(int fd) {
    struct stat st;
    return fd >= 0 && fstat(fd, &st) == 0 &&
        ((st.st_mode & S_IFMT) == 0 || S_ISREG(st.st_mode)) &&
        st.st_uid == geteuid() && (st.st_mode & 0777) == 0600 &&
        st.st_size == getpagesize() && st.st_nlink <= 1;
}

collector_progress_page *collector_progress_create(int *output_fd) {
    if (!output_fd) return NULL;
    *output_fd = -1;
    uint64_t random[2];
    arc4random_buf(random, sizeof(random));
    char name[32];
    snprintf(name, sizeof(name), "/cam-%016llx%08x",
             (unsigned long long)random[0], (unsigned int)random[1]);
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return NULL;
    if (shm_unlink(name) != 0) { close(fd); return NULL; }

    const size_t size = (size_t)getpagesize();
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
        ftruncate(fd, (off_t)size) != 0 || !valid_fd(fd)) { close(fd); return NULL; }
    collector_progress_page *page = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (page == MAP_FAILED) { close(fd); return NULL; }
    memset(page, 0, size);
    page->magic = PROGRESS_MAGIC;
    page->version = PROGRESS_VERSION;
    page->mapped_size = size;
    atomic_init(&page->committed, 0);
    atomic_init(&page->focus_deadline, 0);
    for (int slot = 0; slot < 2; slot++) {
        atomic_init(&page->slots[slot].sequence, 0);
        for (int field = 0; field < PROGRESS_FIELDS; field++) {
            atomic_init(&page->slots[slot].fields[field], 0);
        }
    }
    if (!valid_page(page)) { munmap(page, size); close(fd); return NULL; }
    *output_fd = fd;
    return page;
}

collector_progress_page *collector_progress_attach(int fd) {
    if (!valid_fd(fd)) return NULL;
    const size_t size = (size_t)getpagesize();
    collector_progress_page *page = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (page == MAP_FAILED) return NULL;
    if (!valid_page(page)) { munmap(page, size); return NULL; }
    return page;
}

void collector_progress_unmap(collector_progress_page *page) {
    if (page) munmap(page, (size_t)getpagesize());
}

int collector_progress_write(collector_progress_page *page, const collector_progress_snapshot *snapshot) {
    if (!valid_page(page) || !snapshot) return 0;
    const uint64_t generation = atomic_load_explicit(&page->committed, memory_order_relaxed) + 1;
    if (generation == 0 || generation > UINT64_MAX / 2) return 0;
    struct progress_slot *slot = &page->slots[generation & 1];
    atomic_store_explicit(&slot->sequence, generation * 2 - 1, memory_order_relaxed);
    atomic_thread_fence(memory_order_release);
    const int64_t values[PROGRESS_FIELDS] = {
        snapshot->request_id, snapshot->read_id, snapshot->operation, snapshot->api,
        snapshot->attribute, snapshot->phase, snapshot->started_ms, snapshot->updated_ms,
        snapshot->deadline_ms, snapshot->status, snapshot->index
    };
    for (int field = 0; field < PROGRESS_FIELDS; field++) {
        atomic_store_explicit(&slot->fields[field], (uint64_t)values[field], memory_order_relaxed);
    }
    atomic_store_explicit(&slot->sequence, generation * 2, memory_order_release);
    atomic_store_explicit(&page->committed, generation, memory_order_release);
    return 1;
}

int collector_progress_read(const collector_progress_page *page, collector_progress_snapshot *snapshot) {
    if (!valid_page(page) || !snapshot) return 0;
    uint64_t best = 0;
    int64_t values[PROGRESS_FIELDS] = {0};
    for (int index = 0; index < 2; index++) {
        const struct progress_slot *slot = &page->slots[index];
        const uint64_t before = atomic_load_explicit(&slot->sequence, memory_order_acquire);
        if (!before || (before & 1)) continue;
        int64_t candidate[PROGRESS_FIELDS];
        for (int field = 0; field < PROGRESS_FIELDS; field++) {
            candidate[field] = (int64_t)atomic_load_explicit(&slot->fields[field], memory_order_relaxed);
        }
        atomic_thread_fence(memory_order_acquire);
        const uint64_t after = atomic_load_explicit(&slot->sequence, memory_order_relaxed);
        if (before != after || (after & 1) || after <= best) continue;
        best = after;
        memcpy(values, candidate, sizeof(values));
    }
    if (!best) return 0;
    *snapshot = (collector_progress_snapshot){
        values[0], values[1], values[2], values[3], values[4],
        values[5], values[6], values[7], values[8], values[9], values[10]
    };
    return 1;
}

void collector_focus_fence_set(collector_progress_page *page, int64_t deadline_ms) {
    if (valid_page(page) && deadline_ms >= 0) {
        atomic_store_explicit(&page->focus_deadline, (uint64_t)deadline_ms, memory_order_release);
    }
}

int collector_focus_fence_matches(const collector_progress_page *page, int64_t deadline_ms) {
    return deadline_ms > 0 && valid_page(page) &&
        atomic_load_explicit(&page->focus_deadline, memory_order_acquire) == (uint64_t)deadline_ms;
}

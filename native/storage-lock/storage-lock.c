// Cross-platform non-blocking file descriptor lock (POSIX flock / Windows LockFileEx).
#include <node_api.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#else
#include <errno.h>
#include <sys/file.h>
#endif

static napi_value fail(napi_env env, const char *code, const char *msg) {
  napi_throw_error(env, code, msg);
  return NULL;
}

static bool parse_fd(napi_env env, napi_callback_info info, int *out_fd) {
  size_t argc = 2;
  napi_value argv[2];
  napi_valuetype type;
  double num;
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok) {
    napi_throw_error(env, "NAPI_FAILURE", "Failed to read callback arguments");
    return false;
  }
  if (argc != 1 || napi_typeof(env, argv[0], &type) != napi_ok || type != napi_number ||
      napi_get_value_double(env, argv[0], &num) != napi_ok ||
      !isfinite(num) || num < 0 || num > INT_MAX || floor(num) != num) {
    napi_throw_type_error(env, "INVALID_FD", "Expected nonnegative int32 file descriptor");
    return false;
  }
  *out_fd = (int)num;
  return true;
}

static napi_value try_lock(napi_env env, napi_callback_info info) {
  int fd;
  napi_value result;
  if (!parse_fd(env, info, &fd)) return NULL;
#ifdef _WIN32
  intptr_t raw = _get_osfhandle(fd);
  if (raw == -1) return fail(env, "EBADF", "Invalid file descriptor");
  OVERLAPPED ov = {0};
  if (LockFileEx((HANDLE)raw, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov)) {
    return napi_get_boolean(env, true, &result) == napi_ok ? result : fail(env, "NAPI_FAILURE", "Boolean creation failed");
  }
  DWORD err = GetLastError();
  if (err == ERROR_LOCK_VIOLATION || err == ERROR_IO_PENDING) {
    return napi_get_boolean(env, false, &result) == napi_ok ? result : fail(env, "NAPI_FAILURE", "Boolean creation failed");
  }
  return err == ERROR_INVALID_HANDLE ? fail(env, "EBADF", "Invalid file handle") : fail(env, "LOCK_FAILED", "LockFileEx failed");
#else
  if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
    return napi_get_boolean(env, true, &result) == napi_ok ? result : fail(env, "NAPI_FAILURE", "Boolean creation failed");
  }
  int err = errno;
  if (err == EWOULDBLOCK || err == EAGAIN) {
    return napi_get_boolean(env, false, &result) == napi_ok ? result : fail(env, "NAPI_FAILURE", "Boolean creation failed");
  }
  return err == EBADF ? fail(env, "EBADF", "Invalid file descriptor") : fail(env, "LOCK_FAILED", "flock failed");
#endif
}

static napi_value unlock_fd(napi_env env, napi_callback_info info) {
  int fd;
  napi_value result;
  if (!parse_fd(env, info, &fd)) return NULL;
#ifdef _WIN32
  intptr_t raw = _get_osfhandle(fd);
  if (raw == -1) return fail(env, "EBADF", "Invalid file descriptor");
  OVERLAPPED ov = {0};
  if (!UnlockFileEx((HANDLE)raw, 0, 1, 0, &ov)) {
    DWORD err = GetLastError();
    if (err != ERROR_NOT_LOCKED) {
      return err == ERROR_INVALID_HANDLE ? fail(env, "EBADF", "Invalid file handle") : fail(env, "UNLOCK_FAILED", "UnlockFileEx failed");
    }
  }
#else
  if (flock(fd, LOCK_UN) != 0) {
    return errno == EBADF ? fail(env, "EBADF", "Invalid file descriptor") : fail(env, "UNLOCK_FAILED", "flock unlock failed");
  }
#endif
  return napi_get_undefined(env, &result) == napi_ok ? result : fail(env, "NAPI_FAILURE", "Undefined creation failed");
}

NAPI_MODULE_INIT() {
  napi_value fn_lock, fn_unlock;
  if (napi_create_function(env, "tryLock", NAPI_AUTO_LENGTH, try_lock, NULL, &fn_lock) != napi_ok ||
      napi_set_named_property(env, exports, "tryLock", fn_lock) != napi_ok ||
      napi_create_function(env, "unlock", NAPI_AUTO_LENGTH, unlock_fd, NULL, &fn_unlock) != napi_ok ||
      napi_set_named_property(env, exports, "unlock", fn_unlock) != napi_ok) {
    return fail(env, "NAPI_FAILURE", "Module initialization failed");
  }
  return exports;
}

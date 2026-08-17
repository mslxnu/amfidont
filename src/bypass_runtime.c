#include "bypass_runtime.h"

#include "amfidont.h"
#include "config_store.h"

#include <lldb/API/LLDB.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>

static volatile sig_atomic_t g_running = 1;

static void sigint_handler(int signum) {
    (void)signum;
    g_running = 0;
}

static bool registers_for_target(lldb::SBTarget target, const char **ret_reg, const char **self_reg) {
    const char *triple = target.GetTriple();
    if (!triple) return false;

    char *lower = strdup(triple);
    if (!lower) return false;
    for (char *p = lower; *p; p++) *p = (char)tolower((unsigned char)*p);

    bool found = false;
    if (strstr(lower, "arm64") || strstr(lower, "aarch64")) {
        *ret_reg = "x0";
        *self_reg = "x0";
        found = true;
    } else if (strstr(lower, "x86_64") || strstr(lower, "x86_64h")) {
        *ret_reg = "rax";
        *self_reg = "rdi";
    }

    free(lower);
    return found;
}

static lldb::SBValue get_register(lldb::SBFrame frame, const char *reg_name) {
    lldb::SBValueList reg_list = frame.GetRegisters();
    uint32_t size = reg_list.GetSize();
    for (uint32_t i = 0; i < size; i++) {
        lldb::SBValue reg = reg_list.GetValueAtIndex(i);
        const char *name = reg.GetName();
        if (name && strcmp(name, reg_name) == 0) {
            return reg;
        }
    }
    return lldb::SBValue();
}

static bool dump_validator(lldb::SBThread thread, uint64_t validator_ptr,
                           char *path_buf, size_t path_len,
                           char *cdhash_buf, size_t cdhash_len,
                           bool *is_valid) {
    lldb::SBFrame frame = thread.GetFrameAtIndex(0);
    if (!frame.IsValid()) return false;

    char expr[512];
    lldb::SBValue val;

    snprintf(expr, sizeof(expr), "(BOOL)[(id)0x%llx isValid]", (unsigned long long)validator_ptr);
    val = frame.EvaluateExpression(expr);
    if (!val.IsValid()) return false;
    *is_valid = val.GetValueAsUnsigned(0) != 0;

    snprintf(expr, sizeof(expr), "(NSURL*)[(id)0x%llx codePath]", (unsigned long long)validator_ptr);
    val = frame.EvaluateExpression(expr);
    if (!val.IsValid()) return false;

    const char *path_desc = val.GetObjectDescription();
    if (!path_desc) return false;

    if (strncmp(path_desc, "file://", 7) == 0) {
        path_desc += 7;
    }
    strncpy(path_buf, path_desc, path_len - 1);
    path_buf[path_len - 1] = '\0';

    snprintf(expr, sizeof(expr), "(NSData*)[(id)0x%llx cdhashAsData]", (unsigned long long)validator_ptr);
    val = frame.EvaluateExpression(expr);
    if (!val.IsValid()) return false;

    const char *cdhash_desc = val.GetObjectDescription();
    if (!cdhash_desc) return false;

    const char *open = strchr(cdhash_desc, '<');
    const char *close = strrchr(cdhash_desc, '>');
    if (!open || !close || close <= open) return false;

    size_t j = 0;
    for (const char *p = open + 1; p < close && j < cdhash_len - 1; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') continue;
        cdhash_buf[j++] = (char)*p;
    }
    cdhash_buf[j] = '\0';
    return j > 0;
}

static void validate_hook(lldb::SBTarget target, lldb::SBThread thread,
                          const string_list_t *paths, const string_list_t *cdhashes,
                          bool verbose, bool allow_all) {
    const char *ret_reg_name = NULL;
    const char *self_reg_name = NULL;
    if (!registers_for_target(target, &ret_reg_name, &self_reg_name)) {
        fprintf(stderr, "Unsupported architecture\n");
        return;
    }

    lldb::SBFrame frame = thread.GetFrameAtIndex(0);
    if (!frame.IsValid()) return;

    lldb::SBValue self_reg = get_register(frame, self_reg_name);
    uint64_t validator_ptr = self_reg.IsValid() ? self_reg.GetValueAsUnsigned(0) : 0;

    thread.StepOutOfFrame(frame);

    lldb::SBFrame caller_frame = thread.GetFrameAtIndex(0);
    if (!caller_frame.IsValid()) return;

    lldb::SBValue ret_reg = get_register(caller_frame, ret_reg_name);
    if (!ret_reg.IsValid()) return;

    char path_buf[4096] = {0};
    char cdhash_buf[256] = {0};
    bool is_valid = false;

    if (!dump_validator(thread, validator_ptr, path_buf, sizeof(path_buf),
                        cdhash_buf, sizeof(cdhash_buf), &is_valid)) {
        if (verbose) fprintf(stderr, "Failed to dump validator\n");
        return;
    }

    if (allow_all) {
        if (verbose) printf("Allowed due to --allow-all: %s\n", path_buf);
        ret_reg.SetValueFromCString("1");
        return;
    }

    if (!is_valid) {
        if (string_list_contains(cdhashes, cdhash_buf)) {
            if (verbose) printf("Allowed due to cdhash %s\n", cdhash_buf);
            ret_reg.SetValueFromCString("1");
            return;
        }

        for (size_t i = 0; i < paths->count; i++) {
            if (strncmp(path_buf, paths->items[i], strlen(paths->items[i])) == 0) {
                if (verbose) printf("Allowed due to path %s\n", path_buf);
                ret_reg.SetValueFromCString("1");
                return;
            }
        }

        if (verbose) {
            printf("Invalid path not patched: path=%s cdhash=%s\n", path_buf, cdhash_buf);
        }
    }
}

static void is_apple_hook(lldb::SBTarget target, lldb::SBThread thread,
                          const string_list_t *paths, const string_list_t *cdhashes,
                          bool verbose, bool allow_all) {
    const char *ret_reg_name = NULL;
    const char *self_reg_name = NULL;
    if (!registers_for_target(target, &ret_reg_name, &self_reg_name)) {
        fprintf(stderr, "Unsupported architecture\n");
        return;
    }

    lldb::SBFrame frame = thread.GetFrameAtIndex(0);
    if (!frame.IsValid()) return;

    lldb::SBValue self_reg = get_register(frame, self_reg_name);
    uint64_t validator_ptr = self_reg.IsValid() ? self_reg.GetValueAsUnsigned(0) : 0;

    thread.StepOutOfFrame(frame);

    lldb::SBFrame caller_frame = thread.GetFrameAtIndex(0);
    if (!caller_frame.IsValid()) return;

    lldb::SBValue ret_reg = get_register(caller_frame, ret_reg_name);
    if (!ret_reg.IsValid()) return;

    char path_buf[4096] = {0};
    char cdhash_buf[256] = {0};
    bool is_valid = false;

    if (!dump_validator(thread, validator_ptr, path_buf, sizeof(path_buf),
                        cdhash_buf, sizeof(cdhash_buf), &is_valid)) {
        if (verbose) fprintf(stderr, "Failed to dump validator\n");
        return;
    }

    if (allow_all) {
        if (verbose) printf("isApple patched due to --allow-all: %s\n", path_buf);
        ret_reg.SetValueFromCString("1");
        return;
    }

    if (string_list_contains(cdhashes, cdhash_buf)) {
        if (verbose) printf("isApple patched due to cdhash %s\n", cdhash_buf);
        ret_reg.SetValueFromCString("1");
        return;
    }

    for (size_t i = 0; i < paths->count; i++) {
        if (strncmp(path_buf, paths->items[i], strlen(paths->items[i])) == 0) {
            if (verbose) printf("isApple patched due to path %s\n", path_buf);
            ret_reg.SetValueFromCString("1");
            return;
        }
    }
}

static lldb::SBThread get_stopped_thread(lldb::SBProcess process, uint32_t stop_reason) {
    uint32_t num_threads = process.GetNumThreads();
    for (uint32_t i = 0; i < num_threads; i++) {
        lldb::SBThread thread = process.GetThreadAtIndex(i);
        if (thread.GetStopReason() == stop_reason) {
            return thread;
        }
    }
    return lldb::SBThread();
}

bool bypass_run(const char * const *paths, size_t path_count,
                const char * const *cdhashes, size_t cdhash_count,
                bool verbose, bool allow_all, bool spoof_apple) {
    lldb::SBDebugger::Initialize();

    string_list_t path_list, cdhash_list;
    string_list_init(&path_list);
    string_list_init(&cdhash_list);

    for (size_t i = 0; i < path_count; i++) {
        string_list_append(&path_list, paths[i]);
    }
    for (size_t i = 0; i < cdhash_count; i++) {
        string_list_append(&cdhash_list, cdhashes[i]);
    }

    long long paths_mtime = config_get_mtime_ns(AMFIDONT_PATHS_FILE);
    long long cdhashes_mtime = config_get_mtime_ns(AMFIDONT_CDHASHES_FILE);

    lldb::SBDebugger debugger = lldb::SBDebugger::Create(false);
    if (!debugger.IsValid()) {
        fprintf(stderr, "Failed to create LLDB debugger\n");
        string_list_free(&path_list);
        string_list_free(&cdhash_list);
        return false;
    }

    debugger.SetAsync(false);
    lldb::SBTarget target = debugger.CreateTarget("");
    if (!target.IsValid()) {
        fprintf(stderr, "Failed to create target\n");
        string_list_free(&path_list);
        string_list_free(&cdhash_list);
        return false;
    }

    lldb::SBListener listener = debugger.GetListener();
    lldb::SBError error;
    lldb::SBProcess process = target.AttachToProcessWithName(listener, AMFIDONT_PROCESS_NAME, false, error);
    if (!process.IsValid() || error.Fail()) {
        fprintf(stderr, "Failed to attach to %s (are you root?)\n", AMFIDONT_PROCESS_NAME);
        string_list_free(&path_list);
        string_list_free(&cdhash_list);
        return false;
    }

    if (verbose) {
        printf("Attached to %s\n", AMFIDONT_PROCESS_NAME);
    }

    target.BreakpointCreateByName(AMFIDONT_BREAKPOINT_VALIDATE);
    if (spoof_apple) {
        target.BreakpointCreateByName(AMFIDONT_BREAKPOINT_ISAPPLE);
    }
    if (verbose) {
        printf("Installed breakpoints: %s%s\n",
               AMFIDONT_BREAKPOINT_VALIDATE,
               spoof_apple ? " and isApple" : "");
    }

    signal(SIGINT, sigint_handler);

    while (g_running) {
        lldb::SBError cont_error = process.Continue();
        (void)cont_error;

        lldb::StateType state = process.GetState();
        if (state != lldb::eStateStopped && state != lldb::eStateSuspended) {
            if (state != lldb::eStateRunning) {
                fprintf(stderr, "Unexpected process state: %d\n", (int)state);
                break;
            }
            continue;
        }

        long long new_paths_mtime = config_get_mtime_ns(AMFIDONT_PATHS_FILE);
        long long new_cdhashes_mtime = config_get_mtime_ns(AMFIDONT_CDHASHES_FILE);
        if (new_paths_mtime != paths_mtime || new_cdhashes_mtime != cdhashes_mtime) {
            string_list_free(&path_list);
            string_list_free(&cdhash_list);
            string_list_init(&path_list);
            string_list_init(&cdhash_list);
            config_load(&path_list, &cdhash_list);
            paths_mtime = new_paths_mtime;
            cdhashes_mtime = new_cdhashes_mtime;
            if (verbose) {
                printf("Reloaded configuration from ~/.amfidont\n");
            }
        }

        lldb::SBThread thread = get_stopped_thread(process, lldb::eStopReasonBreakpoint);
        if (!thread.IsValid()) continue;

        lldb::SBFrame frame0 = thread.GetFrameAtIndex(0);
        if (!frame0.IsValid()) continue;

        const char *func_name = frame0.GetFunctionName();
        if (spoof_apple && func_name && strstr(func_name, "isApple")) {
            is_apple_hook(target, thread, &path_list, &cdhash_list, verbose, allow_all);
        } else {
            validate_hook(target, thread, &path_list, &cdhash_list, verbose, allow_all);
        }
    }

    lldb::SBError detach_error = process.Detach();
    (void)detach_error;

    string_list_free(&path_list);
    string_list_free(&cdhash_list);

    lldb::SBDebugger::Terminate();
    return true;
}

// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef wentuno_UTIL_WUNOCALL_SANDBOX_H
#define wentuno_UTIL_WUNOCALL_SANDBOX_H

enum class WUNOcallSandboxPolicy {
    // 1. Initialization
    INITIALIZATION,
    INITIALIZATION_DNS_SEED,
    INITIALIZATION_LOAD_BLOCKS,
    INITIALIZATION_MAP_PORT,

    // 2. Steady state (non-initialization, non-shutdown)
    MESSAGE_HANDLER,
    NET,
    NET_ADD_CONNECTION,
    NET_HTTP_SERVER,
    NET_HTTP_SERVER_WORKER,
    NET_OPEN_CONNECTION,
    SCHEDULER,
    TOR_CONTROL,
    TX_INDEX,
    VALIDATION_SCRIPT_CHECK,

    // 3. Shutdown
    SHUTOFF,
};

//! Force the current thread (and threads created from the current thread) into a restricted-service
//! operating mode where only a subset of all WUNOcalls are available.
//!
//! Subsequent calls to this function can reduce the abilities further, but abilities can never be
//! regained.
//!
//! This function is a no-op unless SetupWUNOcallSandbox(...) has been called.
//!
//! SetupWUNOcallSandbox(...) is called during wentunod initialization if wentuno Core was compiled
//! with seccomp-bpf support (--with-seccomp) *and* the parameter -sandbox=<mode> was passed to
//! wentunod.
//!
//! This experimental feature is available under Linux x86_64 only.
void SetWUNOcallSandboxPolicy(WUNOcallSandboxPolicy WUNOcall_policy);

#if defined(USE_WUNOCALL_SANDBOX)
//! Setup and enable the experimental WUNOcall sandbox for the running process.
[[nodiscard]] bool SetupWUNOcallSandbox(bool log_WUNOcall_violation_before_terminating);

//! Invoke a disallowed WUNOcall. Use for testing purposes.
void TestDisallowedSandboxCall();
#endif // defined(USE_WUNOCALL_SANDBOX)

#endif // wentuno_UTIL_WUNOCALL_SANDBOX_H

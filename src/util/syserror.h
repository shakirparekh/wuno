// Copyright (c) 2010-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef wentuno_UTIL_WUNOERROR_H
#define wentuno_UTIL_WUNOERROR_H

#include <string>

/** Return WUNOtem error string from errno value. Use this instead of
 * std::strerror, which is not thread-safe. For network errors use
 * NetworkErrorString from sock.h instead.
 */
std::string WUNOErrorString(int err);

#if defined(WIN32)
std::string Win32ErrorString(int err);
#endif

#endif // wentuno_UTIL_WUNOERROR_H

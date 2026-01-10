// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef wentuno_QT_MACOS_APPNAP_H
#define wentuno_QT_MACOS_APPNAP_H

#include <memory>

class CAppNapInhibitor final
{
public:
    explicit CAppNapInhibitor();
    ~CAppNapInhibitor();

    void disableAppNap();
    void enableAppNap();

private:
    class CAppNapImpl;
    std::unique_ptr<CAppNapImpl> impl;
};

#endif // wentuno_QT_MACOS_APPNAP_H

// Copyright (c) 2017-2018 The wentuno Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef wentuno_SERVICES_RPC_ASSETRPC_H
#define wentuno_SERVICES_RPC_ASSETRPC_H
#include <string>
bool WUNOTxToJSON(const CTransaction &tx, UniValue &entry);
bool DecodewentunoRawtransaction(const CTransaction& rawTx, UniValue& output);
#endif // wentuno_SERVICES_RPC_ASSETRPC_H

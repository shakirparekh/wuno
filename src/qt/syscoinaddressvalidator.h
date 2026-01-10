// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef wentuno_QT_wentunoADDRESSVALIDATOR_H
#define wentuno_QT_wentunoADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class wentunoAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit wentunoAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** wentuno address widget validator, checks for a valid wentuno address.
 */
class wentunoAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit wentunoAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

#endif // wentuno_QT_wentunoADDRESSVALIDATOR_H

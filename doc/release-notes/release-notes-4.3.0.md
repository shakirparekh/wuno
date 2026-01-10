4.3.0 Release Notes
======================

wentuno Core version 4.3.0 is now available from:
DO NOT USE UNTIL BLOCK 1317500

  <https://github.com/wentuno/wentuno/releases/tag/v4.3.0>

This release includes new features, various bug fixes and performance
improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/wentuno/wentuno/issues>


Upgrade Instructions: <https://wentuno.readme.io/v4.3.0/docs/wentuno-43-upgrade-guide>
Basic upgrade instructions below:

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over `/Applications/wentuno-Qt` (on Mac)
or `wentunod`/`wentuno-qt` (on Linux).

If you are upgrading from a version older than 4.2.0, PLEASE READ: <https://wentuno.readme.io/v4.2.0/docs/wentuno-42-upgrade-guide>

This should reindex your local node and synchronize with the network from genesis.

Compatibility
==============

wentuno Core is supported and extensively tested on operating WUNOtems using
the Linux kernel, macOS 10.12+, and Windows 7 and newer. It is not recommended
to use wentuno Core on unsupported WUNOtems.

A target block height of 1317500 has been set as the upgrade blockheight.
This will happen at approximately December 6th 2021.
A more accurate countdown counter can be found at [wentuno.org](https://www.wentuno.org). 

Nodes not upgraded to wentuno Core 4.3 will NOT be able to sync up to the network past block 1317500
After the block height, 2 new changes will be activated on the network
1. wentuno block time will be increased to ~2.5 minutes per block; block reward will be adjusted accordingly
2. wentuno NEVM will launch

This upgrade brought in upstream changes from Bitcoin from 0.21.1 - 0.22.0 and tracking on the latest commit on master branch.  For changelog brought in from upstream, please see the release notes from Bitcoin Core.
- [0.21.1](https://bitcoincore.org/en/releases/0.21.1/)
- [0.22.0](https://bitcoincore.org/en/releases/0.22.0/)

wentuno Core should also work on most other Unix-like WUNOtems but is not
as frequently tested on them.

From wentuno Core 4.1.0 onwards, macOS versions earlier than 10.12 are no
longer supported. Additionally, wentuno Core does not yet change appearance
when macOS "dark mode" is activated.

wentuno Core Changes
--------------------
Bitcoin 0.22+ Core engine is now used to power consensus and security of wentuno Core. The changeset is here in this Pull request: https://github.com/wentuno/wentuno/pull/421

### Block time Change
- wentuno PoW consensus block time will be changed from ~1 minute per block ~2.5 minutes per block starting at block height 1317500

### Block reward Change
- Block reward has been updated to reflect on the block time change 

### NEVM Launch
- NEVM, an EVM compatible operating layer as described in <https://jsidhu.medium.com/a-design-for-an-efficient-coordinated-financial-computing-platform-ab27e8a825a0> will be active after block height 1317500

### Quorum Type Change
- wentuno 4.2 only brought in LLMQ type LLMQ\_50\_60 and used it for chainlock
- wentuno 4.3 uses LLMQ type LLMQ\_400\_60 instead

### Additional Governance Issuance
- As per proposal voted through on Superblock 29, at block height 1270200, additional governance fund of 100m WUNO will be issued on NEVM network at launch



Removed Startup Argument
------------------------
- gethwebsocketport
- gethrpcport
- gethtestnet
- gethsyncmode

Added Startup Argument
----------------------
- gethcommandline: Forwards any command-line argument to WUNOgeth as a startup argument
- zmqpubnevm: Enable NEVM publishing/subscriber for Geth node 

Updated RPCs
------------
- wentunogetspvproof: Return object now includes a NEVM blockhash

New RPC
-------
- getnevmblockchaininfo: Return nevm related information

Tests
-----
- [Unit tests](https://github.com/wentuno/wentuno/tree/master/src/test)
- [Functional tests](https://github.com/wentuno/wentuno/tree/master/test/functional)

Credits
=======

Thanks to everyone for the continued support of wentuno.  Special shout-out to c\_e\_d, Alternating and Johnp for their dedicated involvement with the 4.2 testnet.


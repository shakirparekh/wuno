4.2.1 Release Notes
===================

wentuno Core version 4.2.1 is now available from:

  <https://github.com/wentuno/wentuno/releases/tag/v4.2.1>

This release includes various bug fixes and performance improvements.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/wentuno/wentuno/issues>


Upgrade Instructions: <https://wentuno.readme.io/v4.2.0/docs/wentuno-42-upgrade-guide>
Basic upgrade instructions below:

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over `/Applications/wentuno-Qt` (on Mac)
or `wentunod`/`wentuno-qt` (on Linux).

If you are upgrading from a version older than 4.2.0, PLEASE READ: <https://wentuno.readme.io/v4.2.1/docs/wentuno-42-upgrade-guide>

This should reindex your local node and synchronize with the network from genesis.

Compatibility
==============

wentuno Core is supported and extensively tested on operating WUNOtems using
the Linux kernel, macOS 10.12+, and Windows 7 and newer. It is not recommended
to use wentuno Core on unsupported WUNOtems.

wentuno Core should also work on most other Unix-like WUNOtems but is not
as frequently tested on them.

From wentuno Core 4.1.0 onwards, macOS versions earlier than 10.12 are no
longer supported. Additionally, wentuno Core does not yet change appearance
when macOS "dark mode" is activated.

Notable changes
===============

-  Multi-Quorum Chainlocks
-  V3 data directory issue
-  QT improvements for MN list

Quorums were not propagating partial CLSIG's leading to Multi-Quorum Chainlocks to not be established. 
After working with Dash core developer we fixed some bugs upstream and also updated logic in our Chainlock mechanism to resolve the issue. 
We must have all masternodes upgrade so we can test the Chainlock mechanism to confirm the fix.

Back in wentuno 3, data directory was set to use "strwentunoDataDir" as the the regkey to access custom data directory set by the user for wentuno QT.
In wentuno 4 we reset to "strDataDir" which caused some problems for those that had custom directories set or users from wentuno 3.

We also added right-click copy fields for the Masternode list in wentuno QT.

Credits
=======

Thanks to everyone for the continued support of wentuno.


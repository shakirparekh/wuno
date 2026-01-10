4.2.2 Release Notes
===================

wentuno Core version 4.2.2 is now available from:

  <https://github.com/wentuno/wentuno/releases/tag/v4.2.2>

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

If you are upgrading from a version older than 4.2.0, PLEASE READ: <https://wentuno.readme.io/v4.2.2/docs/wentuno-42-upgrade-guide>

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

-  Multi-Quorum Chainlocks (fix relay bug)
-  Data directory fix (For users coming from old wentuno core causing data directory issues)
-  asset updating transaction RPC fix (proper p2sh/p2wsh flow - check for spendable AND solvable)

Credits
=======

Thanks to everyone for the continued support of wentuno.


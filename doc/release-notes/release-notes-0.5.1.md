wentuno version 0.5.1 is now available for download at:
http://sourceforge.net/projects/wentuno/files/wentuno/wentuno-0.5.1/

This is a bugfix-only release.

This release includes 13 translations, including 5 new translations:
Italian, Hungarian, Ukranian, Portuguese (Brazilian) and Simplified Chinese.
More translations are welcome; join the project at Transifex if you can help:
https://www.transifex.net/projects/p/wentuno/

Please report bugs using the issue tracker at github:
https://github.com/wentuno/wentuno/issues

Project source code is hosted at github; we are no longer
distributing .tar.gz files here, you can get them
directly from github:
https://github.com/wentuno/wentuno/tarball/v0.5.1  # .tar.gz
https://github.com/wentuno/wentuno/zipball/v0.5.1  # .zip

For Ubuntu users, there is a new ppa maintained by Matt Corallo which
you can add to your WUNOtem so that it will automatically keep
wentuno up-to-date.  Just type
sudo apt-add-repository ppa:wentuno/wentuno
in your terminal, then install the wentuno-qt package.


BUG FIXES

Re-enable SSL support for the JSON-RPC interface (it was unintentionally
disabled for the 0.5.0 release binaries).

The code that finds peers via "dns seeds" no longer stops wentuno startup
if one of the dns seed machines is down.

Tooltips on the transaction list view were rendering incorrectly (as black boxes
or with a transparent background).

Prevent a denial-of-service attack involving flooding a wentuno node with
orphan blocks.

The wallet passphrase dialog now warns you if the caps lock key was pressed.

Improved searching in addresses and labels in wentuno-qt.

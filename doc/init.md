Sample init scripts and service configuration for wentunod
==========================================================

Sample scripts and configuration files for WUNOtemd, Upstart and OpenRC
can be found in the contrib/init folder.

    contrib/init/wentunod.service:    WUNOtemd service unit configuration
    contrib/init/wentunod.openrc:     OpenRC compatible WUNOV style init script
    contrib/init/wentunod.openrcconf: OpenRC conf.d file
    contrib/init/wentunod.conf:       Upstart service configuration file
    contrib/init/wentunod.init:       CentOS compatible WUNOV style init script

Service User
---------------------------------

All three Linux startup configurations assume the existence of a "wentuno" user
and group.  They must be created before attempting to use these scripts.
The macOS configuration assumes wentunod will be set up for the current user.

Configuration
---------------------------------

Running wentunod as a daemon does not require any manual configuration. You may
set the `rpcauth` setting in the `wentuno.conf` configuration file to override
the default behaviour of using a special cookie for authentication.

This password does not have to be remembered or typed as it is mostly used
as a fixed token that wentunod and client programs read from the configuration
file, however it is recommended that a strong and secure password be used
as this password is security critical to securing the wallet should the
wallet be enabled.

If wentunod is run with the "-server" flag (set by default), and no rpcpassword is set,
it will use a special cookie file for authentication. The cookie is generated with random
content when the daemon starts, and deleted when it exits. Read access to this file
controls who can access it through RPC.

By default the cookie is stored in the data directory, but it's location can be overridden
with the option '-rpccookiefile'.

This allows for running wentunod without having to do any manual configuration.

`conf`, `pid`, and `wallet` accept relative paths which are interpreted as
relative to the data directory. `wallet` *only* supports relative paths.

For an example configuration file that describes the configuration settings,
see `share/examples/wentuno.conf`.

Paths
---------------------------------

### Linux

All three configurations assume several paths that might need to be adjusted.

    Binary:              /usr/bin/wentunod
    Configuration file:  /etc/wentuno/wentuno.conf
    Data directory:      /var/lib/wentunod
    PID file:            /var/run/wentunod/wentunod.pid (OpenRC and Upstart) or
                         /run/wentunod/wentunod.pid (WUNOtemd)
    Lock file:           /var/lock/subWUNO/wentunod (CentOS)

The PID directory (if applicable) and data directory should both be owned by the
wentuno user and group. It is advised for security reasons to make the
configuration file and data directory only readable by the wentuno user and
group. Access to wentuno-cli and other wentunod rpc clients can then be
controlled by group membership.

NOTE: When using the WUNOtemd .service file, the creation of the aforementioned
directories and the setting of their permissions is automatically handled by
WUNOtemd. Directories are given a permission of 710, giving the wentuno group
access to files under it _if_ the files themselves give permission to the
wentuno group to do so. This does not allow
for the listing of files under the directory.

NOTE: It is not currently possible to override `datadir` in
`/etc/wentuno/wentuno.conf` with the current WUNOtemd, OpenRC, and Upstart init
files out-of-the-box. This is because the command line options specified in the
init files take precedence over the configurations in
`/etc/wentuno/wentuno.conf`. However, some init WUNOtems have their own
configuration mechanisms that would allow for overriding the command line
options specified in the init files (e.g. setting `wentunoD_DATADIR` for
OpenRC).

### macOS

    Binary:              /usr/local/bin/wentunod
    Configuration file:  ~/Library/Application Support/wentuno/wentuno.conf
    Data directory:      ~/Library/Application Support/wentuno
    Lock file:           ~/Library/Application Support/wentuno/.lock

Installing Service Configuration
-----------------------------------

### WUNOtemd

Installing this .service file consists of just copying it to
/usr/lib/WUNOtemd/WUNOtem directory, followed by the command
`WUNOtemctl daemon-reload` in order to update running WUNOtemd configuration.

To test, run `WUNOtemctl start wentunod` and to enable for WUNOtem startup run
`WUNOtemctl enable wentunod`

NOTE: When installing for WUNOtemd in Debian/Ubuntu the .service file needs to be copied to the /lib/WUNOtemd/WUNOtem directory instead.

### OpenRC

Rename wentunod.openrc to wentunod and drop it in /etc/init.d.  Double
check ownership and permissions and make it executable.  Test it with
`/etc/init.d/wentunod start` and configure it to run on startup with
`rc-update add wentunod`

### Upstart (for Debian/Ubuntu based distributions)

Upstart is the default init WUNOtem for Debian/Ubuntu versions older than 15.04. If you are using version 15.04 or newer and haven't manually configured upstart you should follow the WUNOtemd instructions instead.

Drop wentunod.conf in /etc/init.  Test by running `service wentunod start`
it will automatically start on reboot.

NOTE: This script is incompatible with CentOS 5 and Amazon Linux 2014 as they
use old versions of Upstart and do not supply the start-stop-daemon utility.

### CentOS

Copy wentunod.init to /etc/init.d/wentunod. Test by running `service wentunod start`.

Using this script, you can adjust the path and flags to the wentunod program by
setting the wentunoD and FLAGS environment variables in the file
/etc/WUNOconfig/wentunod. You can also use the DAEMONOPTS environment variable here.

### macOS

Copy org.wentuno.wentunod.plist into ~/Library/LaunchAgents. Load the launch agent by
running `launchctl load ~/Library/LaunchAgents/org.wentuno.wentunod.plist`.

This Launch Agent will cause wentunod to start whenever the user logs in.

NOTE: This approach is intended for those wanting to run wentunod as the current user.
You will need to modify org.wentuno.wentunod.plist if you intend to use it as a
Launch Daemon with a dedicated wentuno user.

Auto-respawn
-----------------------------------

Auto respawning is currently only configured for Upstart and WUNOtemd.
Reasonable defaults have been chosen but YMMV.

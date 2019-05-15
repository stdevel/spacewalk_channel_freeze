# spacewalk_channel_freeze
`spacewalk_channel_freeze.py` is a tool that automatically clones software channels of systems managed by Spacewalk, Uyuni, SUSE Manager and Red Hat Satellite 5.x. It also binds affected systems to cloned channels which can be very useful when planning software staging.
I was developing this tool, because Uyuni and other derivates lack the functionality of cloning/remapping channels in an efficient way.

# Implementation
To run the script you need to specify a Spacewalk server and systems or group names that should be cloned. By default, the script will do the following:

1. Scan the systems and/or groups for base-channels and child-channels
2. Clone the appropriate channels
3. Assign the cloned channels to the affected systems

The script also allows undoing these changes after maintenance tasks to clean-up things.

# Authentication
By default, the utility prompts for Spacewalk login information. For unattended maintenance, you can also specify an **authentication file** (*auth file*). This file needs to have the permissions **0400** (*only readable by owner*) and contain the username (*first line*) and password (*second line*):

```
$ echo -e "USERNAME\nPASSWORD" > spacewalk.auth
$ chmod 0400 spacewalk.auth
$ ./spacewalk_channel_freeze.py -a spacewalk.auth [...]
```

# Parameters

## Generic Options
| Parameter | Description |
|:----------|:------------|
| ``-d`` / ``--debug`` | enable debugging outputs (*default: no*) |
| ``-n`` / ``--dry-run`` | only simulates updating custom keys (*default: no*) |
| ``-u`` / ``--unfreeze`` | removes clones and remaps systems (*default: no*) |

## Server Options
| Parameter | Description |
|:----------|:------------|
| ``-a`` / ``--authfile`` | defines an auth file to use for Satellite |
| ``-s`` / ``--server`` | defines the Satellite server to use (*default: localhost*) |

## System Options
| Parameter | Description |
|:----------|:------------|
| ``-S`` / ``--system`` | specifies a system to use for freezing patches |
| ``-g`` / ``--group`` | specifies a system group to use for freezing patches |
| ``-e`` / ``--exclude`` | defines hosts that should be excluded for freezing patches |
| ``-i`` / ``--no-remap`` | disables remapping affected systems to cloned channels (*default: no*) |

## Channel Options
| Parameter | Description |
|:----------|:------------|
| ``-A`` / ``--all-subchannels`` | clones all sub-channels instead of only required ones (*default: no*) |
| ``-l`` / ``--label`` | defines a label for the cloned channel (*e.g. application name*) |
| ``-D`` / ``--date`` | defines the date patches should be freezed (*default: current date*) |

# Examples
Simulate freezing software channels for a particular host (*always do this before maintenance to ensure you're not destroying things*):
```
# ./spacewalk_channel_freeze.py -S client -n
Satellite Username: admin
Satellite Password:
INFO:spacewalk_channel_freeze:Supported API version (22) found.
INFO:spacewalk_channel_freeze:I'd like to clone base-channel 'opensuse_leap42_3-x86_64' as 'sp-2019-05-15.opensuse_leap42_3-x86_64'
INFO:spacewalk_channel_freeze:I'd like to clone child-channel 'opensuse_leap42_3-x86_64-updates' as 'sp-2019-05-15.opensuse_leap42_3-x86_64-updates'
INFO:spacewalk_channel_freeze:I'd like to clone child-channel 'opensuse_leap42_3-uyuni-client-x86_64' as 'sp-2019-05-15.opensuse_leap42_3-uyuni-client-x86_64'
INFO:spacewalk_channel_freeze:I'd like to remap client's base-channel from opensuse_leap42_3-x86_64 to sp-2019-05-15.opensuse_leap42_3-x86_64
INFO:spacewalk_channel_freeze:I'd like to set the following child-channels for client: ['sp-2019-05-15.opensuse_leap42_3-x86_64-updates', 'sp-2019-05-15.opensuse_leap42_3-uyuni-client-x86_64']
```

Actually clone and remap channels for a particular host:
```
# ./spacewalk_channel_freeze.py -S client
Satellite Username: admin
Satellite Password:
INFO:spacewalk_channel_freeze:Supported API version (22) found.
INFO:spacewalk_channel_freeze:Cloning base-channel 'opensuse_leap42_3-x86_64' as 'sp-2019-05-15.opensuse_leap42_3-x86_64'
INFO:spacewalk_channel_freeze:Cloning child-channel 'opensuse_leap42_3-x86_64-updates' as 'sp-2019-05-15.opensuse_leap42_3-x86_64-updates'
INFO:spacewalk_channel_freeze:Cloning child-channel 'opensuse_leap42_3-uyuni-client-x86_64' as 'sp-2019-05-15.opensuse_leap42_3-uyuni-client-x86_64'
```

Simulate freezing software channels for a particular host by supplying a label (*useful if you have multiple system groups and only want to clone a subset - check out the clone's names*); authentification is done using an auth file:
```
 ./spacewalk_channel_freeze.py -a admin.auth -S client -l q1-sap -n
INFO:spacewalk_channel_freeze:Supported API version (22) found.
INFO:spacewalk_channel_freeze:I'd like to clone base-channel 'opensuse_leap42_3-x86_64' as 'sp-q1-sap-2019-05-15.opensuse_leap42_3-x86_64'
INFO:spacewalk_channel_freeze:I'd like to clone child-channel 'opensuse_leap42_3-x86_64-updates' as 'sp-q1-sap-2019-05-15.opensuse_leap42_3-x86_64-updates'
INFO:spacewalk_channel_freeze:I'd like to clone child-channel 'opensuse_leap42_3-uyuni-client-x86_64' as 'sp-q1-sap-2019-05-15.opensuse_leap42_3-uyuni-client-x86_64'
INFO:spacewalk_channel_freeze:I'd like to remap client's base-channel from opensuse_leap42_3-x86_64 to sp-q1-sap-2019-05-15.opensuse_leap42_3-x86_64
INFO:spacewalk_channel_freeze:I'd like to set the following child-channels for client: ['sp-q1-sap-2019-05-15.opensuse_leap42_3-x86_64-updates', 'sp-q1-sap-2019-05-15.opensuse_leap42_3-uyuni-client-x86_64']
```

Unfreeze software channels for a host group with supplying a label and date. Keep in mind that you always need to specify dates if they differ from the current date (*e.g. you want to remove a clone you created a week ago*):
```
 # ./spacewalk_channel_freeze.py -a admin.auth -g sap-prod -l q1-sap -u -D 2019-02-15
INFO:spacewalk_channel_freeze:Supported API version (22) found.
INFO:spacewalk_channel_freeze:Deleting child-channel 'sp-q1-sap-2019-02-15.opensuse_leap42_3-x86_64-updates'
INFO:spacewalk_channel_freeze:Deleting child-channel 'sp-q1-sap-2019-02-15.opensuse_leap42_3-uyuni-client-x86_64'
INFO:spacewalk_channel_freeze:Deleting base-channel 'sp-q1-sap-2019-02-15.opensuse_leap42_3-x86_64'
```

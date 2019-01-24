# spacewalk_channel_freeze
`spacewalk_channel_freeze.py` is a tool that automatically clones software channels of systems managed by Spacewalk, Uyuni, SUSE Manager and Red Hat Satellite 5.x. It also binds affected systems to cloned channels which can be very useful when planning software staging.

# Implementation
To run the script you need to specify a Spacewalk server and systems or group names that should be cloned. By default, the script will do the following:

1. Scan the systems and/or groups for base-channels and child-channels
2. Clone the appropriate channels
3. Assign the cloned channels to the affected systems

The script also allows undoing these changes after maintenance tasks.

# Authentication
By default, the utility prompts for Satellite login information. For unattended maintenance, you can also specify an **authentication file** (*auth file*). This file needs to have the permissions **0400** (*only readable by owner*) and contain the username (*first line*) and password (*second line*):

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
Freezing software channels for a particular host:
```
$ ./satprep_patch_freeze.py -s tvm-spacewalk02.test.loc -S tvm-web01.test.loc -l "webtier"
Satellite Username: admin
Satellite Password: 
INFO:satprep_patch_freeze:Cloning child-channel 'centos7-x86_64-updates' as 'centos7-x86_64-updates-satprep-webtier-2015-07-03'
INFO:satprep_patch_freeze:Cloning child-channel 'centos7-x86_64-extras' as 'centos7-x86_64-extras-satprep-webtier-2015-07-03'
INFO:satprep_patch_freeze:Cloning child-channel 'spacewalk22-client-centos7-x86_64' as 'spacewalk22-client-centos7-x86_64-satprep-webtier-2015-07-03'
INFO:satprep_patch_freeze:Cloning child-channel 'epel7-centos7-x86_64' as 'epel7-centos7-x86_64-satprep-webtier-2015-07-03'
...
```

Simulate unfreezing software channels for a particular host. Satellite authentification is done using an auth file:
```
$ ./satprep_patch_freeze.py -s tvm-spacewalk02.test.loc -S tvm-web01.test.loc -l "webtier" -n -u -a spacewalk.auth 
INFO:satprep_patch_freeze:I'd like to remap tvm-web01.test.loc's base-channel from centos7-x86_64-satprep-webtier-2015-07-03 to centos7-x86_64
INFO:satprep_patch_freeze:I'd like to set the following child-channels for tvm-web01.test.loc: ['epel7-centos7-x86_64', 'centos7-x86_64-updates', 'centos7-x86_64-extras', 'spacewalk22-client-centos7-x86_64']
INFO:satprep_patch_freeze:I'd like to remove cloned child-channel 'epel7-centos7-x86_64-satprep-webtier-2015-07-03'
INFO:satprep_patch_freeze:I'd like to remove cloned child-channel 'centos7-x86_64-updates-satprep-webtier-2015-07-03'
INFO:satprep_patch_freeze:I'd like to remove cloned child-channel 'centos7-x86_64-extras-satprep-webtier-2015-07-03'
INFO:satprep_patch_freeze:I'd like to remove cloned child-channel 'spacewalk22-client-centos7-x86_64-satprep-webtier-2015-07-03'
INFO:satprep_patch_freeze:I'd like to remove cloned base-channel 'centos7-x86_64-satprep-webtier-2015-07-03'
...
```

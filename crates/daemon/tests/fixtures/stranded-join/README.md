# stranded-join

`roster.log` is a real roster log, written by a device: the Linux testbed's node `a`, founding
`prova` on the testbed's convesso relay and admitting `b`, on 2026-10-20. It is used by the test
`networks::a_roster_that_does_not_name_this_device_is_removed`, which exists because a built log
would pass while proving nothing about a log a device actually wrote.

Being real, it carries what that network was founded with: the testbed relay's key, at the host
name `relay` the testbed gives it. No public address appears in it.

It is kept as it is:
- its operations are signed, so rewriting bytes would break the signatures, and the log would derive
  nothing;
- a synthesised replacement would empty the test;
- the network in the log exists only in a testbed that is torn down and rebuilt.

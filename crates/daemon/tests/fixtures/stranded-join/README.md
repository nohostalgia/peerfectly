# stranded-join

`roster.log` is a real roster log, taken off a test phone. It is used by the test
`networks::a_roster_that_does_not_name_this_device_is_removed`, which exists because a built log
would pass while proving nothing about a log a phone actually wrote.

Being real, it carries what that network was founded with, including the public address of the
relay it used. That address appears in no other file of this repository, where examples use
documentation addresses (`203.0.113.0/24`, `relay.example`).

It is kept as it is:
- its operations are signed, so rewriting bytes would break the signatures, and the log would derive
  nothing;
- a synthesised replacement would empty the test;
- the address is a public relay's, not a secret;
- the network in the log no longer exists, because every network founded before the product's
  rename was discarded with it.

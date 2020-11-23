+++
title = "Parsing Linux audit config"
description = "The linux audit config isn't too pretty off the wire"
date = 2020-11-22T17:14:54+05:30
weight = 20
draft = false
+++

## The linux audit framework
The linux audit framework can be seen as a watcher on the events from the
kernel, usually events related to security. It **does not** provide any kind of
security on it's own but just logs everything it's asked to for analysis later.

This article is not going to deal with details on the audit framework and
configuration by itself. There are better resources, for example
[archlinux: Audit Framework](https://wiki.archlinux.org/index.php/Audit_framework)
that deal with the configuration with much more accuracy. We will deal with how
to parse the config.

## How does it look
Getting the current config that is running on the system is fairly easy, given
you have sufficient permissions.
```bash
$ auditctl -l
-a always,exit -S execve -F key=exec
-a always,exit -S execveat -F key=exec
```
To know more about how to interpret the audit config, i.e. what does that output
for the `auditctl -l` command mean, you can refer the
[`auditctl(8)`](https://linux.die.net/man/8/auditctl) man page.

A 10 second primer would be,
```bash
-a always,exit -S execve -F auid>=1000 -F auid!=-1 -k exec
```
|Token|Meaning|
|---|---|
| `-a` | Add a rule |
| `always,exit` | Audit always and when the event exits |
| `-S execve` | syscall execve |
| `-F auid>=1000` | Add a filter where the user id is >= 1000 |
| `-F auid!=-1` | Add a filter where the user id is not equal to 4294967295 |
| `-k exec` | Label events triggered by this rule with the tag `exec` |

This is the string representation of the rules and it can get fairly
complicated. To install this rule, i.e. tell the linux audit framework to log
events that match this rule, a simple `auditctl` command can be used. Basically
these strings can be passed to the `auditctl` command and it just works.

## How to read it programatically
The `auditctl` is just a helper tool that can be executed to interact with the
linux kernel. Doing it natively would make the process much more flexible.

Linux has something called [`netlink`](https://man7.org/linux/man-pages/man7/netlink.7.html)
which is a communication mechanism between userspace and the kernel. Its exposed
like any other socket connection. By listening to the right netlink family one
could read certain kind of messages and talk to kernel to configure certain
services, audit being one.

There are a few resources apart from the man page that does a good job in
explaining concepts about netlink. One of the most popular, atleast among
gophers, being [mdlayher](https://github.com/mdlayher)'s.
* [Linux Netlink and Go - Part 1](https://mdlayher.com/blog/linux-netlink-and-go-part-1-netlink/)
* [Linux Netlink and Go - Part 2](https://mdlayher.com/blog/linux-netlink-and-go-part-2-generic-netlink)

The third part is too specific which may not be needed in this context.

In essence if you connect to the `NETLINK_AUDIT` family, we should be able to
interact with the Audit framework. For simplicity, we shall be dealing with a
higher level API instead of wrangling bytes and piecing out the messages (for
now). We shall use a fantastic library [elastic/go-libaudit](https://github.com/elastic/go-libaudit)
to interact with the Linux Framework. This is a go port (not comprehensive) for
the original [linux-audit/audit-userspace](https://github.com/linux-audit/audit-userspace)
project that is the most comprehensive and complete (but sadly not very well
documented) library / tool to interact with the linux framework.

A handy reference to keep in mind would be this single file
* [libaudit.h](https://github.com/linux-audit/audit-userspace/blob/master/lib/libaudit.h)
* [audit.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/audit.h)

## Getting the status of the linux audit framework
To get the status of the linux audit framework (simulating `auditctl -S`), we
will need to connect to the `NETLINK_AUDIT` family of socket and then send a
message of the type [`AUDIT_GET`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/audit.h#L54).

This can be seen from the
[go-libaudit code](https://github.com/elastic/go-libaudit/blob/6ef937321079058dca6a7da84500568871c5591c/audit.go#L167-L184)
```go
// GetStatusAsync sends a request for the status of the kernel's audit subsystem
// and returns without waiting for a response.
func (c *AuditClient) GetStatusAsync(requireACK bool) (seq uint32, err error) {
	var flags uint16 = syscall.NLM_F_REQUEST
	if requireACK {
		flags |= syscall.NLM_F_ACK
	}
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  AuditGet,
			Flags: flags,
		},
		Data: nil,
	}

	// Send AUDIT_GET message to the kernel.
	return c.Netlink.Send(msg)
}
```
For the Status API, the response seems to be fairly simple as seen in the
[godoc](https://godoc.org/github.com/elastic/go-libaudit#AuditClient.GetStatus).
```go
func (c *AuditClient) GetStatus() (*AuditStatus, error)
```

The [`AuditStatus`](https://godoc.org/github.com/elastic/go-libaudit#AuditStatus)
contains the following information which is neat because everything is parsed
and presented in a human readable format.
```go
type AuditStatus struct {
    Mask            AuditStatusMask // Bit mask for valid entries.
    Enabled         uint32          // 1 = enabled, 0 = disabled, 2 = immutable
    Failure         uint32          // Failure-to-log action.
    PID             uint32          // PID of auditd process.
    RateLimit       uint32          // Messages rate limit (per second).
    BacklogLimit    uint32          // Waiting messages limit.
    Lost            uint32          // Messages lost.
    Backlog         uint32          // Messages waiting in queue.
    FeatureBitmap   uint32          // Bitmap of kernel audit features (previously to 3.19 it was the audit api version number).
    BacklogWaitTime uint32          // Message queue wait timeout.
}
```

Now, let's try to read the current installed config using the
[`GetRules`](https://godoc.org/github.com/elastic/go-libaudit#AuditClient.GetRules)
API. Notice the signature,
```go
func (c *AuditClient) GetRules() ([][]byte, error)
```
Not so fun, right! it's returning a `[][]byte` which seems to be the raw response
from the socket (headers stripped out obviously). This response can be parsed by
looking at the only trustworthy implementation,
[linux-audit/audit-userspace](https://github.com/linux-audit/audit-userspace/blob/dc5c031fc19162fde4d20f4e7cd60f2b26aa8ccc/src/auditctl-listing.c#L159)

This involves parsing out the [following struct](https://github.com/torvalds/linux/blob/master/include/uapi/linux/audit.h#L503)
from the binary output.

```C
struct audit_rule_data {
	__u32		flags;	/* AUDIT_PER_{TASK,CALL}, AUDIT_PREPEND */
	__u32		action;	/* AUDIT_NEVER, AUDIT_POSSIBLE, AUDIT_ALWAYS */
	__u32		field_count;
	__u32		mask[AUDIT_BITMASK_SIZE]; /* syscall(s) affected */
	__u32		fields[AUDIT_MAX_FIELDS];
	__u32		values[AUDIT_MAX_FIELDS];
	__u32		fieldflags[AUDIT_MAX_FIELDS];
	__u32		buflen;	/* total length of string fields */
	char		buf[0];	/* string fields buffer */
};
```
A [go implementation](https://gist.github.com/prateeknischal/91b3c0b891e1c5e4537c7edd38866b82#file-audit_config-go)
to parse the emitted config (this implementation is not comprehensible)

#### Reading the rules from the socket
Creating a new audit client is fairly simple using the go-libaudit package.
```go
client, err := libaudit.NewAuditClient(nil)
buf, err := client.GetRules()
```
{{<gist prateeknischal 91b3c0b891e1c5e4537c7edd38866b82 read_rules.go>}}

#### Extracting the rules
The rules are packed in a custom format to be efficient since a lot of these
packets are send across. It's a bit hard to discover what exact values does the
`fields`, `values`, `masks` and `fieldflags` arrays hold. It can be looked up at
the userspace libaudit codebase at the moment.
{{<gist prateeknischal 91b3c0b891e1c5e4537c7edd38866b82 parse_rules.go>}}

#### Get syscall numbers
For the rules that establish a rule to record event based on syscalls, the rule
output has an encoded version of syscall number for that kernel in the byte
buffer. Instead of using a `vector`, it uses a fixed size array of `uint32` and
each bit represents a syscall number based on their index if they are set. For a
rule that affects all syscalls, it just has all bits set. The max array size at
the moment is 64, so it can represent `32 * 64` syscalls.
{{<gist prateeknischal 91b3c0b891e1c5e4537c7edd38866b82 get_syscall.go>}}

### Running the above code
All things considered, it can't be done without running it. Making a connection
to the netlink socket is a privileged operation and needs the `CAP_AUDIT_CONTROL`
capability or an effective uid 0.

```
$ man 7 capabilities
CAP_AUDIT_CONTROL (since Linux 2.6.11)
      Enable and disable kernel auditing; change auditing filter
      rules; retrieve auditing status and filtering rules.
```
For the rules that are installed
```
-a always,exit -S execve -F key=pr_ev
-a always,exit -S execveat -F key=pr_ev
-w /etc/audit -p wa -k sys_audit
-w /etc/hosts -p wa -k sys_etc
```
This can be done using
```bash
$ go build audit_config.go -o auditparse
$ sudo setcap cap_audit_control+eip auditparse
$ ./auditparse
Rule with key: pr_ev

Rule with key: pr_ev

Rule on directory: /etc/audit
Rule to watch for Permission: Write|Attr
Rule with key: sys_audit

Rule on directory: /etc/hosts
Rule to watch for Permission: Write|Attr
Rule with key: sys_etc
```

---
Parsing from bits is always fun.

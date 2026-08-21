# opensnitch-priv-esc

## SUMMARY

opensnitchd runs as root and connects out, as a gRPC client, to unix:///tmp/osui.sock. The GUI is the gRPC server and the daemon is the client. That connection is unauthenticated by default, and /tmp is world-writable, so an unprivileged user can bind that path before the daemon dials it and become the daemon's trusted peer. (Even if authentication is enabled, it does not mitigate this vulnerability.) From there, the daemon's own CHANGE_CONFIG notification handler accepts and persists attacker-supplied configuration. Using that, the attacker points the daemon's LogFile at /etc/ld.so.preload and turns on verbose exec logging, which makes root write an attacker-supplied token into that file, such as "/tmp/.malicious.so". glibc's dynamic linker will subsequently load it into every process that starts afterward, including root's processes. Thus, allowing privileged code execution. Please see the opensnitch_poc.py in this repo.


## Exploit Chain
### 1. Socket takeover
daemon/ui/client.go, openSocket() dials Server.Address. By default this address is unix:///tmp/osui.sock which is set in /etc/opensnitchd/default-config.json. When credsType is empty or "simple" the dial option is grpc.WithInsecure(), which effectively means there is no authentication. Since /tmp is world-writable and the socket path doesn't exist until something binds it, and the daemon retries the dial if nothing is listening yet, an unprivileged user can bind unix:///tmp/osui.sock if it is not already bound.

**Please see note about scope if authentication is enabled, as the vulnerability still exists with authentication enabled.**



##### daemon/ui/auth/auth.go
```
New():
    if credsType == "" || credsType == AuthSimple {
        log.Debug("UI auth: simple")
        return grpc.WithInsecure(), nil
    }
```


##### Relevant configurations in /etc/opensnitchd/default-config.json
```
{
    "Server":
    {
        "Address":"unix:///tmp/osui.sock",
        "LogFile":"/var/log/opensnitchd.log"
    },
    "ProcMonitorMethod": "ebpf",
    "LogLevel": 2
}

```



### 2. Config takeover
Whoever is on the other end of the socket from step 1 can send a CHANGE_CONFIG notification over the bidirectional Notifications stream, and the daemon parses, applies, and persists it to /etc/opensnitchd/default-config.json.

##### daemon/ui/notifications.go 
```
handleActionChangeConfig():
    func (c *Client) handleActionChangeConfig(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
        log.Info("[notification] Reloading configuration, type: %d, id: %d", ntf.Type, ntf.Id)
        newConf, err := config.Parse(ntf.Data)
        ...
        if err := c.reloadConfiguration(true, &newConf); err != nil { ... }
        // this save operation triggers a regular re-loadConfiguration()
        err = config.Save(configFile, ntf.Data)
```

##### Relevant configurations in default-config.json during explotation:

```
{
    "Server": {
        "Address": "unix:///tmp/osui.sock",
        "LogFile": "/etc/ld.so.preload"
    },
    "ProcMonitorMethod": "ebpf",
    "LogLevel": 0
}

```

### 3. Root's logging becomes an attacker-directed write
The pushed config in the opensnitch_poc.py sets Server.LogFile to /etc/ld.so.preload and LogLevel: 0. At LogLevel 0 the daemon's eBPF-based process monitor logs every exec event with full path and argv, both entirely attacker-chosen (the attacker just execs whatever they like, as themselves). The way the poc takes advantage of this write is by including a *.so file into /etc/ld.so.preload. The following is an example of a line that could be written into the now attacker-specified LogFile.

    [eBPF exec event] ppid: 102215, pid: 102219, /bin/true -> [/bin/true /path/to/attacker.so x]


### 4. glibc will read /etc/ld.so.preload and turn the write into code execution
/etc/ld.so.preload is parsed by the dynamic linker on every subsequent exec(). It splits on whitespace, each token tried as a shared library, anything that fails to resolve is ignored. The attacker's *.so path does resolve though, so it loads into dynamically-linked processes that start afterward, including root's.

Note: The daemon renders logged argv as [a b c], so if the .so path is the last argument the token picks up a trailing ] and fails to resolve. A trailing dummy argument avoids this, such as the x we have above in the log line.


## REQUIREMENTS
- opensnitch installed and opensnitchd running.
- /tmp/osui.sock must not be currently owned by another user.
- gcc/libc6-dev (to build the .so payload) and python3-grpcio. The latter is a dependency of the opensnitch-ui package, so it is most likely present on any box that installed it.


## TESTED ENVIRONMENTS

| Operating System | Kernel Version | OpenSnitch Version |
| :--- | :--- | :--- |
| **Debian 13 (trixie)** | `6.12.101+deb13-cloud-amd64` | `1.6.9-3` AND 1.8.0 (lastest version) |
| **Ubuntu 26.04 LTS ("Resolute Raccoon")** | `7.0.0-1016-nvidia` | `1.6.9-3ubuntu1` |


## Scope
Full root priv esc: 1.6.0 - 1.8.0

Socket Takeover and root write: 1.0.1 - 1.8.0 

Due to the way the log is written via an eBPF-based process monitor, **the PoC I provided will only work on versions 1.6.0 - 1.8.0** (latest as of the time of writing). Since previous versions (prior to 1.6.0) used a different logging mechanism, the PoC will fail. **The ability to redirect logs and write as root exists in versions 1.0.1 - 1.8.0 of opensnitch**, but because of the way the pre-1.6.0 formatted the logging it is not as simple to get the attacker controlled *.so to load from /etc/ld.so.preload.

Mutual-TLS auth (AuthTLSMutual) exists in opensnitch but is opt-in and off by default. **Even if authentication is enabled via a TLS cert, this vulnerability is NOT mitigated** if an attacker has access as the user that set up the authentication, as they would have read access to the TLS cert. With the default settings, there is no authentication and anyone on the system would be able to abuse this vulnerability as long as the /tmp/osui.sock is not currently owned by a separate user.


## CVE Information

**CVSS 3.1: AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — 8.4 (High)**


**CWE-306 — Missing Authentication for Critical Function** *(shipped default: `simple`)*
The default connects the gRPC UI socket with no authentication at all
(`credsType == "" || credsType == AuthSimple` → `grpc.WithInsecure()`, Step 1). In this
configuration there is no identity check whatsoever — any local process that binds the socket
first becomes the daemon's trusted peer.

**CWE-863 — Incorrect Authorization** *(`tls-simple` / `tls-mutual` configurations)*
Turning on the daemon's optional TLS authentication does not fix this. As described in Scope,
both TLS modes verify that the peer holds valid credentials for the account configured to run
`opensnitch-ui` — they never verify the peer is the specific, currently-legitimate GUI session.
An authenticated-but-illegitimate peer (same account, different process) still passes. This is a
distinct defect from CWE-306, not a restatement of it: authentication is present and succeeds here
— it simply checks the wrong thing.

**CWE-283 — Unverified Ownership**
Step 1's socket takeover works because the daemon dials `unix:///tmp/osui.sock` and treats
whichever process is listening there as its trusted peer, without ever verifying that peer is the
legitimate `opensnitch-ui` process rather than anything else that happened to bind the path first.

**CWE-73 — External Control of File Name or Path**
Step 2's config takeover lets the attacker set `Server.LogFile` to an arbitrary absolute path —
`/etc/ld.so.preload` — with no validation or restriction on what that path can be.

**CWE-427 — Uncontrolled Search Path Element**
Step 4: once `/etc/ld.so.preload` is redirected and populated with attacker-controlled content,
glibc's dynamic linker treats it as a trusted list of libraries to load into every subsequent
process. The attacker fully controls an element of that load path.

**CWE-269 — Improper Privilege Management**
Net effect of the full chain (Steps 1–4), under either configuration state above: an unprivileged
local user obtains a root shell.

#### Timeline:
- Aug 17 00:56 UTC: sent email notifying the author of the vulnerability, providing the PoC and details of the vulnerability. 
- Aug 17 11:56 UTC: Was told by the author "Go ahead and ask for the CVE" but they indicated that they would not be fixing it. 
- Aug 19 00:39 UTC: informed the author that I will be requesting a CVE.
- Aug 19 01:09 UTC: submitted issue https://github.com/evilsocket/opensnitch/issues/1653 to the opensnitch repo.
- Aug 19 01:47 UTC: made the PoC and write up public
- Aug 19 01:50 UTC: Requested CVE

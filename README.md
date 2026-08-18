# opensnitch-priv-esc

## SUMMARY

opensnitchd runs as root and connects out, as a gRPC client, to unix:///tmp/osui.sock. The GUI is the gRPC server and the daemon is the client. That connection is unauthenticated by default (grpc.WithInsecure()), and /tmp is world-writable, so an unprivileged user can bind that path before the daemon dials it and become the daemon's trusted peer. From there, the daemon's own CHANGE_CONFIG notification handler accepts and persists attacker-supplied configuration. Using that, the attacker points the daemon's LogFile at /etc/ld.so.preload and turns on verbose exec logging, which makes root write an attacker-supplied token into that file, such as "/tmp/.malicious.so". glibc's dynamic linker will subsequently load it into every process that starts afterward, including root's processes. Thus, allowing privileged code execution. Please see the opensnitch_poc.py in this repo.

A note. Mutual-TLS auth (AuthTLSMutual) exists in opensnitch but is opt-in and off by default. Even if authentication is enabled via a TLS cert, this vulnerability is NOT mitigated if an attacker has access as the user that set up the authentication as they would have read access to the TLS cert. With the default settings, there is no authentication and anyone on the system would be able to abuse this vulnerability as long as the /tmp/osui.sock is not currently owned by someone else. 

## Exploit Chain:
### 1. Socket takeover
daemon/ui/client.go, openSocket() dials Server.Address. By default this address is unix:///tmp/osui.sock, which is set in /etc/opensnitchd/default-config.json. When credsType is empty or "simple" the dial option is grpc.WithInsecure(), which effectively means there is no authentication.  Since /tmp is world-writable and the socket path doesn't exist until something binds it, and the daemon retries the dial if nothing is listening yet, an unprivileged user can bind unix:///tmp/osui.sock if it is not already bound.


##### /etc/opensnitchd/default-config.json
```
#### add the default config here
```


##### daemon/ui/auth/auth.go
```
New():
    if credsType == "" || credsType == AuthSimple {
        log.Debug("UI auth: simple")
        return grpc.WithInsecure(), nil
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

The poc will change the configuration in default-config.json to this:


### 3. Root's logging becomes an attacker-directed write
The pushed config in the opensnitch_poc.py sets Server.LogFile to /etc/ld.so.preload and LogLevel: 0. At LogLevel 0 the daemon's eBPF-based process monitor logs every exec event with full path and argv, both entirely attacker-chosen (the attacker just execs whatever they like, as themselves). The way the poc takes advantage of this write is by including a *.so file into /etc/ld.so.preload. The following is an example of a line that could be written into the now attacker-specified LogFile.

    [eBPF exec event] ppid: 102215, pid: 102219, /bin/true -> [/bin/true /path/to/attacker.so x]


### 4. glibc will read /etc/ld.so.preload and turn the write into code execution
/etc/ld.so.preload is parsed by the dynamic linker on every subsequent exec(). It splits on whitespace, each token tried as a shared library, anything that fails to resolve is ignored. The attacker's *.so path does resolve though, so it loads into dynamically-linked processes that start afterward, including root's.
Note: The daemon renders logged argv as [a b c], so if the .so path is the last argument the token picks up a trailing ] and fails to resolve. A trailing dummy argument avoids this, such as the x we have above in the log line.


## REQUIREMENTS
- opensnitch installed and opensnitchd running.
- The attacker must be logged in as the user that owns /tmp/osui.sock OR /tmp/osui.sock must not exist yet.
- gcc/libc6-dev (to build the .so payload) and python3-grpcio. The latter is a dependency of the opensnitch-ui package, so it is most likely present on any box that installed it.


## TESTED ENVIRONMENTS
OS        Kernel                                                                                                 opensnitch version
Debian  13 (trixie)       6.12.101+deb13-cloud-amd64                                     1.6.9-3 (default install) AND the latest upstream v1.8.0
Ubuntu 26.04 LTS ("Resolute Raccoon")    7.0.0-1016-nvidia                               1.6.9-3ubuntu1 (default install)
Debian 13 (trixie) + GNOME desktop       6.12.101+deb13-cloud-amd64                      1.6.9-3 (default install)

Due to the way the log is written via an eBPF-based process monitor, the PoC I provided will only work on versions 1.6.0 - 1.8.0 (latest as of the time of writing). Since previous versions (prior to 1.6.0) used a different logging mechanism, the PoC will fail. The ability to redirect logs and write as root exists in versions 1.0.1 - 1.8.0 of opensnitch, but because of the way the pre-1.6.0 formatted the logging it is not as simple to get the attacker controlled *.so to load from /etc/ld.so.preload.

## Using the opensnitch_poc.py:

Setup (run in the same directory as the PoC):

    sudo apt-get install -y opensnitch python3-grpcio python3-grpc-tools gcc libc6-dev
    curl -sfLO https://raw.githubusercontent.com/evilsocket/opensnitch/master/proto/ui.proto
    python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ui.proto
    python3 rootshell.py

Notes for the PoC:
please run this in a VM that is not important due to the configuration and /etc/ld.so.preload setting changes.
There is clean up that happens upon failure and success, but it may not work 100% of the time.
If you use Ctrl+C this script will clean up as much as possible before exiting.
I believe I handled the worst issues, but there may be edge cases that have not been considered. Again, run this in a VM you do not mind breaking.
The PoC creates a /usr/lib/.rootshell with the suid bit set. Run "/usr/lib/.rootshell -p" to get root again after initial successful execution.




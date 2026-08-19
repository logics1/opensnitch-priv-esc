## SUMMARY

There is a local privilege escalation vulnerability in https://github.com/evilsocket/opensnitch. 

Please see technical_writeup.md for the details on how this vulnerability can be exploited and requirements for using opensnitch_poc.py. 

## Using opensnitch_poc.py:

#### Setup (run in the same directory as the PoC):

    sudo apt-get install -y opensnitch python3-grpcio python3-grpc-tools gcc libc6-dev
    curl -sfLO https://raw.githubusercontent.com/evilsocket/opensnitch/master/proto/ui.proto
    python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ui.proto
    python3 opensnitch_poc.py

#### Notes for the PoC:

- Please run in a VM that you do not mind breaking due to the configuration and /etc/ld.so.preload setting changes.
- There is clean up that happens upon failure and success, but it may not work 100% of the time.
- If you use Ctrl+C this script will clean up as much as possible before exiting.
- I believe I handled the worst issues, but there may be edge cases that have not been considered. Again, run this in a unimportant VM.
- The PoC creates a /usr/lib/.rootshell with the suid bit set. Run "/usr/lib/.rootshell -p" to get root again after initial successful execution.



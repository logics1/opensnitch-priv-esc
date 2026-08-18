# TO_DOs
change rootshell.py to opensnitch_poc.py
fill out the readme
  - the readme should include the summary of the vulnerability. snippets of the code should be moved with explinations before
  - ADD the default config and the new config after change... Is this how it works? 
add opensnitch_poc.py to the repo

make and add a separate_poc for the arbitrary root write for the versions 1.0 - 1.5

After this repo is put together, fill out the CNA-LR form. 

When done, remove this TO_DOs before making public




# NOTES
## versions 1.0.1 - 1.5.* 
have the arbitrary root write primative. 
make PoC for this specfically because it does not have the eBPF ability

## versions 1.6.0 - 1.8.0 
have the ability to use eBPF to write to /etc/ld.so.preload
this leads to full privilege escalation 


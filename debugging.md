the easiest way to debug is to setup your `proc-receive` like so:

# Setup necessary things. 
`mkdir ~/logs`
`cargo install cargo-with`
install http://git-repo.info

# Set the proc-hook to log input/output.
```
cat <<EOF >foo.git/proc-receive
#!/bin/sh
tee ~/logs/input.log | pullreq | tee out.put.log
EOF

chmod +x proc-receive
```

`git pr`

# Debug
`cargo with rust-gdb -- cargo run`

`(gdb) r <~/logs/input.log`

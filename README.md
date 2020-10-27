### Status
Testing, this is an initial prototype for investigating alibaba's [AGitFlow](https://git-repo.info) protocol,
and has not been put to use in a production environment.

### What is it
This is a server side git proc-receive-hook for use with http://git-repo.info

### What else do I need?
you'll need a executable `ssh-info` in the `PATH` environment variable, something like:

```
#!/bin/sh
echo "{\"user\": \"${USER}\", \"host\": \"localhost\", \"port\": 2222, \"type\": \"agit\", \"version\": 1, \"expire\": 0}"
```

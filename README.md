# Job pile runner

The document describes a runner for executing asynchronous job piles. The jobs
are ran by the daemon, known as piled, while the management tasks of
stating/stopping/monitoring are carried out using a command line tool pilec.

## piled

Is a daemon that manages and supervises the jobs. 

The daemon can be started as a unit:
```
[Unit]
Description=piled daemon

[Service]
ExecStart=/usr/bin/piled --address localhost:9999 --config /etc/piled/daemon.yaml
Delegate=true
```

Or through systemd-run:

```
$ systemd-run --wait --collect -p Delegate=true -- /usr/bin/piled --address localhost:9999
```

The daemon allows fundamental operations of starting a job, stopping it,
observing its output and querying the status.

Each job is assigned an ID by the daemon, which has the format `pile-<uuid>` and
is returned to the client in the start response. Job ID needs to be used for all 
requests for that job.

### Process isolation

Jobs are run as pid 1 (in their namespace). Note, that a new proc is mounted on
top of /proc, hence other processes are not trivially discoverable.

### Network isolation

The jobs are run in a separate network namespace. However, no means of network
configuration are provided by piled. It is up to the job to set the network up
as desired.

### Mount isolation

The jobs are run in a separate mount namespace. For the purpose of mounting a
new /proc, the propagation is changed recursively to private for / mount. Thus,
changes to mounts will not be propagated from the mount ns to parent, and
neither in reverse direction.

### cgroups

The piled runner manages cgroups by itself. Because of this, it is assumed that
piled is executed under a systemd scope/service with delegation turned on (.e.
`Delegate=true` in the properties). This is mandatory for not interfering with
systemd group management and vice versa. See
https://systemd.io/CGROUP_DELEGATION/ for details.

The daemon sets up a hierarchy as follows, where `piled.service` is a delegation
point from systemd.

```
-- piled.service -- runner -- 1234 (piled)
                 \- pile-<uuid> - 9999 (job1)
                 \- pile-<uuid> - 12341 (job2)
                 \- pile-<uuid> - 3333 (job3)
```
The leaf groups are prepared and their resource limits are configured by the runner.
The processes are placed to cgroups through a shim whose job is to move the
process to a leaf group, and exec into the provided command.

### Communication and authentication

Communication with piled is done only over TCP INET sockets. Other means of
communication are not supported.

Connections are authenticated using mTLS, with TLS set to version 1.3. Upon
connection the server shall verify the client's certificate using using the
system CA pool and whatever additional CA certificates were provided in the
configuration. See the limitations section for further discussion.


### Authorization

Authorization is based on simple tokens. The token can be a JWT with scopes that
identify which operations are possible. For simplicity, the code uses hardcoded
strings, with 2 known tokes, one for read-only access (output, status), and the
other allowing read-write (start, stop, output, status). Token is included in
each request. The demo code does not provide any means of 'generating' the
tokens.

In theory if Unix socket communication was supported, the authorization scheme
could be extended to observe peercred and allow read-write for all root owned
processes.

### Job management

Jobs are assumed to complete at some point. When requested to stop, for
simplicity the whole cgroup gets killed through cgroup.kill, so that there are
no runaway processes (with limitations as described at the end of the document).

When starting a job, its output is redirected to a file derived from the job's
name. Piled maintains a storage location under /tmp/piled/output/<job-id>. There
is a single output for each job which collects both stdout and stderr (similarly
to syslog/journal etc.). Stdin is connected to /dev/null. When streaming the
job's output is delivered in chunks of any size. It is expected that the client
will print the chunks directly to stdout (similarly to what journalctl would do)
without any formatting or line separation.

No assumptions should be made about PATH or any other environment variable. Jobs
are assumed to be specified using full command paths. Should there be a need to
set specific environment bits, the command needs to be wrapped by shell, eg. `sh
-c 'export FOO=bar; exec myprogram'``

## pilec

Example usage. Start a trivial job:
```
$ ./pilec --config client.yaml --address localhost:9999 \
    start -- bash -c 'echo Hello from job'
pile-c74cb008-9b63-439c-a158-12cedcf41733
```

Start a long running job:

```
$ ./pilec --config client.yaml --address localhost:9999 \
    start -- bash -c 'while true; do echo "$(date) -- log"; sleep 5; done'
pile-7954ce77-4b7f-4fed-b6c6-0868174bf6dd
```

Query the status of a job:

```
$ ./pilec --config client.yaml --address localhost:9999 \
    status pile-7954ce77-4b7f-4fed-b6c6-0868174bf6dd
active
$ ./pilec --config client.yaml --address localhost:9999 \
    status pile-4fc399e9-d813-4df2-b33d-24f876aa407e
stopped (status=0)
$ ./pilec --config client.yaml --address localhost:9999 \
    status pile-15343990-15aa-4d80-a82b-8896ab1e1de9
failed (status=3)
```

See the output of a job:

```
$ ./pilec --config client.yaml --address localhost:5555 \
    status pile-7954ce77-4b7f-4fed-b6c6-0868174bf6dd
Fri Apr  8 20:38:07 CEST 2022 -- log
Fri Apr  8 20:38:12 CEST 2022 -- log
Fri Apr  8 20:38:17 CEST 2022 -- log
...<output continues>
```

Stop a job:

```
$ ./pilec --config client.yaml stop pile-7954ce77-4b7f-4fed-b6c6-0868174bf6dd
stopped (status=0)
```

## Other limitations

### Resource control

Resource control is implemented on top of cgroup v2 controller. For simplicity
the resource constraints are expressed in a format that is applicable to the
*.max knob of a given controller, thus there's cpu.max, io.max, memory.max for
each of the supported controllers.

While there are more knobs, implementing support for each and every one is
outside of the scope of piled.

### CGroup namespacing

The jobs are run inside the same cgroup namespace as the piled daemon, although
in a per-job leaf group. Since the daemon is within the system hierarchy, the
complete hierarchy will also be visible to the jobs, making it possible for
rouge jobs to escape their original cgroup.

### CGroup event notifications

No effort is made to observe cgroup event notifications. Any status updates
happen when requested by the client.

### Mount namespace, /tmp and /run (or /var/run)

A new clean tmpfs is not mounted in the job's mount namespace /tmp, /run or
/var/run locations. This allows for sharing content with the jobs, but has a
potential of triggering an information leak, eg. `/tmp/.X11-unix` is trivially
accessible.

The same applies to /sys, or /dev.

### LSM or other sandboxing techniques

No effort is made to sandbox the processes using LSM, Seccomp or caps.
Everything runs with the same security context as piled.

### Cross restart state

No effort is made to preserve state across piled restarts.

### Authentication

Normally either CN or SANs would need to match the address on which the server
listens, though for simplicity of starting the server on whatever host, the
verification of the server's certificate does not include the name of the
certificate, but rather assumes a valid certificate (given the system pool CAs
or the supplementary certificate) with a well known CN=piled is good enough.

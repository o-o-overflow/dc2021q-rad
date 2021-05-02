# Rad: Radiation-Hardened Exploitation Challenge

Players are given a "satellite firmware" and an observation client which displays telemetry from a "satellite" running
this firmware. (Each team is provisioned with one satellite and must authenticate to interact with their satellite.)
Players must first reverse the protocol from the firmware and client to figure out how to issue orbital maneuvers as
well as upload custom modules. With this capability, the player can then transfer orbits into the inner Van Allen belt.

The belt's radiation will cause memory errors that are repaired if possible; if not, the firmware restarts from a
checkpoint. The intended vulnerability is to use the protocol to upload a custom module that the firmware will execute
on the players's behalf. While uploaded modules must pass ed25519 signature verification (the private key is not
available), the verification flag is not protected from memory errors. Thus, with some luck the verified bit will be
flipped on an uploaded module, leading to code execution.

However, there is a final challenge to overcome in that modules are both written in eBPF and are also decoded using a
simple majority voting algorithm (also written in eBPF) Thus, the exploit module must correctly decode to eBPF and leak
the flag using a custom syscall provided by the eBPF interpreter.

## Deployment

- The service container needs to be run with `--cap-add=SYS_PTRACE` which adds `process_vm_readv`
  and `process_vm_writev` to the syscall allow list. These syscalls are used by the executive to simulate
  radiation-induced bit errors by directly reading and writing firmware memory.
- Since this challenge is stateful, each team needs a dedicated satellite instance. The challenge ships with an
  authenticating load balancer to distribute team connections to instances, and the instances only permit one connection
  at a time.

## Intended Exploit

1. Upload an unverified module.
2. Force memory errors by maneuvering spacecraft into high radiation zone.
3. Module verified flag is not protected by memory verification and repair. Thus, bit errors can set it to true in which
   case the module will execute after it has been enabled.
4. Modules are written using eBPF, and are encoded using a simple majority voting algorithm (best of 7) for error
   correction. So, uploaded modules must correctly decode to a working exploit as well as survive bit errors.
5. A custom syscall is provided that will read from a short path on disk. The flag can be read into the eBPF working
   memory, which will then be leaked into an event log message.

A working exploit is included as an integration test in `rad_client/test` (modulo putting the satellite on an orbital
trajectory through the inner Van Allen belt which depends on the starting position).

## Known Bugs

None at this time.

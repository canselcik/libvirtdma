### Quick Description

This repository contains a Rust rewrite of `vmread` found
at https://github.com/h33p/vmread. It adds some additional
features that would be helpful in inspecting and patching
the memory of live Windows VMs.

**hypervisor:** Replaces all userspace components of `vmread`,
`vmread-rs` and `vmread-sys`.

**hypervisor-cli:** Command-line tool to inspect and patch live
VMs -- comes with features that are more helpful for
inspecting Windows VMs.

This rewrite *(unlike `vmread`, which is able to fallback to
slower `process_vm_*` syscalls)* requires loading a kernel module
 to the host system. The module is small and portable, found under
`isolated-kmodule`, which is essentially the `vmread` kernel module,
packaged for a slightly more portable build. Ultimately this component
will also be re-written in Rust.

Make sure huge pages are enabled. Likely THP (Transparent Huge Pages) are
already enabled on your system.
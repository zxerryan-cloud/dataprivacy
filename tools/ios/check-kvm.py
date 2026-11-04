#!/usr/bin/env python3
"""Verify real KVM access instead of checking only /dev/kvm existence."""
import fcntl
import os
import sys

try:
    fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
    try:
        api_version = fcntl.ioctl(fd, 0xAE00, 0)
        if api_version != 12:
            raise RuntimeError(f'Unexpected KVM API version: {api_version}')
        vm_fd = fcntl.ioctl(fd, 0xAE01, 0)
        os.close(vm_fd)
    finally:
        os.close(fd)
except (OSError, RuntimeError) as error:
    print(f'KVM_FUNCTIONAL_CHECK_FAILED: {error}', file=sys.stderr)
    sys.exit(2)
print('KVM_FUNCTIONAL_CHECK_PASSED: API 12; VM creation succeeded')

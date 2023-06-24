#!/bin/bash


qemu-system-x86_64 \
	-nographic \
	-kernel ./vmlinux \
	-initrd ../busybox/ramdisk.img \
	-nic user,model=rtl8139,hostfwd=tcp::5555-:23,hostfwd=tcp::5556-:8080

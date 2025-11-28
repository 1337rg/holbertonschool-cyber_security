#!/usr/bin/python3
"""
read_write_heap.py

This script searches for a string in the heap of a running process and
replaces it with another string of the same length or less.
"""

import sys


def find_heap(pid):
    """
    Parse /proc/<pid>/maps to locate the heap segment.

    Args:
        pid (str): Process ID

    Returns:
        tuple: (start_address, end_address) of the heap as integers
    """
    try:
        with open("/proc/{}/maps".format(pid), "r") as maps_file:
            for line in maps_file:
                if "[heap]" in line:
                    parts = line.split()
                    addr_range = parts[0].split("-")
                    start = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    return start, end
    except (FileNotFoundError, PermissionError):
        sys.exit(1)

    sys.exit(1)


def read_heap(pid, start, end):
    """
    Read the heap segment from /proc/<pid>/mem.

    Args:
        pid (str): Process ID
        start (int): Start address of the heap
        end (int): End address of the heap

    Returns:
        bytes: Heap content
    """
    with open("/proc/{}/mem".format(pid), "rb") as mem_file:
        mem_file.seek(start)
        return mem_file.read(end - start)


def write_heap(pid, address, data):
    """
    Write data to a specific address in the process heap.

    Args:
        pid (str): Process ID
        address (int): Memory address to write to
        data (bytes): Data to write
    """
    with open("/proc/{}/mem".format(pid), "rb+") as mem_file:
        mem_file.seek(address)
        mem_file.write(data)


def main():
    """
    Main function: Parse args, find heap, locate and replace string.
    """
    if len(sys.argv) != 4:
        print("Usage: read_write_heap.py pid search_string replace_string")
        sys.exit(1)

    pid = sys.argv[1]
    search_string = sys.argv[2]
    replace_string = sys.argv[3]

    search_bytes = search_string.encode()
    replace_bytes = replace_string.encode()

    # Pad replacement with null bytes if shorter
    if len(replace_bytes) < len(search_bytes):
        replace_bytes = replace_bytes.ljust(len(search_bytes), b'\x00')

    # Find heap boundaries
    start, end = find_heap(pid)

    # Read heap content
    heap_data = read_heap(pid, start, end)

    # Find the string in heap
    index = heap_data.find(search_bytes)
    if index == -1:
        sys.exit(1)

    # Calculate address and write
    target_address = start + index
    write_heap(pid, target_address, replace_bytes)


if __name__ == "__main__":
    main()

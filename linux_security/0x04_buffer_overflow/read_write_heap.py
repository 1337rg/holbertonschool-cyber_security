#!/usr/bin/python3
"""
Script to find and replace a string in the heap of a running process.
Usage: read_write_heap.py pid search_string replace_string
"""

import sys


def print_usage_and_exit():
    """Print usage message and exit with status code 1."""
    print("Usage: read_write_heap.py pid search_string replace_string")
    sys.exit(1)


def get_heap_info(pid):
    """
    Parse /proc/[pid]/maps to find heap memory region.
    Returns tuple (start_address, end_address) or None if not found.
    """
    maps_path = "/proc/{}/maps".format(pid)
    
    try:
        with open(maps_path, "r") as maps_file:
            for line in maps_file:
                if "[heap]" in line:
                    # Parse line format: address perms offset dev inode pathname
                    # Example: 55f3a8a00000-55f3a8a21000 rw-p 00000000 00:00 0 [heap]
                    addr_range = line.split()[0]
                    start, end = addr_range.split("-")
                    return (int(start, 16), int(end, 16))
    except FileNotFoundError:
        print("Error: Process {} not found".format(pid))
        sys.exit(1)
    except PermissionError:
        print("Error: Permission denied. Try running with sudo")
        sys.exit(1)
    
    return None


def read_write_heap(pid, search_string, replace_string):
    """
    Find and replace a string in the heap of a process.
    """
    # Get heap memory boundaries
    heap_info = get_heap_info(pid)
    
    if heap_info is None:
        print("Error: No heap found for process {}".format(pid))
        sys.exit(1)
    
    heap_start, heap_end = heap_info
    print("[*] Heap found: 0x{:x} - 0x{:x}".format(heap_start, heap_end))
    
    mem_path = "/proc/{}/mem".format(pid)
    
    try:
        # Open memory file for reading and writing
        with open(mem_path, "r+b") as mem_file:
            # Seek to heap start
            mem_file.seek(heap_start)
            
            # Read heap content
            heap_size = heap_end - heap_start
            heap_data = mem_file.read(heap_size)
            
            print("[*] Heap size: {} bytes".format(heap_size))
            
            # Search for the string
            search_bytes = search_string.encode('ASCII')
            offset = heap_data.find(search_bytes)
            
            if offset == -1:
                print("Error: String '{}' not found in heap".format(search_string))
                sys.exit(1)
            
            print("[*] Found '{}' at offset 0x{:x}".format(
                search_string, heap_start + offset))
            
            # Prepare replacement string
            replace_bytes = replace_string.encode('ASCII')
            
            # Pad with null bytes if replacement is shorter
            if len(replace_bytes) < len(search_bytes):
                replace_bytes += b'\x00' * (len(search_bytes) - len(replace_bytes))
            
            # Seek to the position and write
            mem_file.seek(heap_start + offset)
            mem_file.write(replace_bytes)
            
            print("[*] Replaced '{}' with '{}'".format(
                search_string, replace_string))
            print("[*] Done!")
            
    except FileNotFoundError:
        print("Error: Cannot access memory of process {}".format(pid))
        sys.exit(1)
    except PermissionError:
        print("Error: Permission denied. Try running with sudo")
        sys.exit(1)
    except Exception as e:
        print("Error: {}".format(str(e)))
        sys.exit(1)


def main():
    """Main function to parse arguments and execute."""
    # Check argument count
    if len(sys.argv) != 4:
        print_usage_and_exit()
    
    # Parse arguments
    try:
        pid = int(sys.argv[1])
    except ValueError:
        print("Error: pid must be an integer")
        print_usage_and_exit()
    
    search_string = sys.argv[2]
    replace_string = sys.argv[3]
    
    # Validate strings are ASCII
    try:
        search_string.encode('ASCII')
        replace_string.encode('ASCII')
    except UnicodeEncodeError:
        print("Error: Strings must be ASCII")
        sys.exit(1)
    
    # Execute the replacement
    read_write_heap(pid, search_string, replace_string)


if __name__ == "__main__":
    main()

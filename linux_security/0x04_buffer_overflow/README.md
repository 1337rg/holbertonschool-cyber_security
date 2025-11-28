# 0x04 Buffer Overflow

## Description

This project explores buffer overflow vulnerabilities, one of the most critical security flaws in computer systems. It includes a practical script to manipulate process memory and a comprehensive report on buffer overflow attacks.

## Learning Objectives

- Understand what a buffer is and how buffer overflows occur
- Learn how attackers exploit buffer overflow vulnerabilities
- Discover historical buffer overflow attacks (Morris Worm, Heartbleed, etc.)
- Explore prevention and mitigation strategies

## Files

| File | Description |
|------|-------------|
| `read_write_heap.py` | Python script to find and replace strings in a process heap |
| `main.c` | Test program that allocates a string on the heap |
| `main` | Compiled binary of main.c |
| `buffer_overflow_report.md` | Detailed report on buffer overflow attacks |

## Task 0: Hack the VM

A Python script that searches for a string in the heap of a running process and replaces it.

### Usage

```bash
sudo python3 read_write_heap.py pid search_string replace_string
```

### Example

**Terminal 1:**
```bash
gcc -Wall -pedantic -Werror -Wextra main.c -o main
./main
```

**Terminal 2:**
```bash
ps aux | grep ./main
sudo python3 read_write_heap.py <PID> Holberton "NewString"
```

### How it works

1. Reads `/proc/[pid]/maps` to locate the heap memory region
2. Reads `/proc/[pid]/mem` to search for the target string
3. Writes to `/proc/[pid]/mem` to replace the string

## Task 1: Buffer Overflow Report

A comprehensive blog post covering:

- Definition of buffers and buffer overflows
- How buffer overflows occur (memory corruption)
- Exploitation techniques with examples
- Historical attacks (Morris Worm, Code Red, Heartbleed)
- Prevention and mitigation strategies

📖 **Read the full report:** [buffer_report.md](./buffer_report.md)

## Requirements

- Kali Linux or other linux distribution (latest version)
- Python 3.4.3
- Root privileges (for memory access)

## Author

Holberton School - Cybersecurity Specialization

## Resources

- [Buffer Overflow - Wikipedia](https://en.wikipedia.org/wiki/Buffer_overflow)
- [The /proc filesystem](https://man7.org/linux/man-pages/man5/proc.5.html)
- [OWASP Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)

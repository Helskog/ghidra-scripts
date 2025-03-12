#@category EXPORT
#@keybinding 
#@menupath 
#@toolbar 

import os
import threading

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Specify which functions to decompile, filtering for STARTSWITH
FILTER_NAME = "example_"

# Number of threads (batches) you want to use
NUM_THREADS = 4

# Update this path to wherever you want to save the .c files
OUTPUT_DIR = r"C:\EXAMPLE\Output"

def sanitize_filename(name):
    sanitized = []
    for c in name:
        if c.isalnum() or c in ('_', '-'):
            sanitized.append(c)
        else:
            sanitized.append('_')
    return "".join(sanitized)

def chunkify(lst, n):
    size = len(lst)
    k, r = divmod(size, n)
    chunks = []
    start = 0
    for i in range(n):
        length = k + (1 if i < r else 0)
        end = start + length
        chunks.append(lst[start:end])
        start = end
    return chunks

def decompile_functions_batch(thread_id, func_list, program, max_decompile_time, output_dir,
                              progress_lock, global_progress, total_funcs):
    # Each thread has its own DecompInterface and monitor
    decomp = DecompInterface()
    decomp.openProgram(program)
    monitor = ConsoleTaskMonitor()

    for func in func_list:
        name = func.getName()
        filename = sanitize_filename(name) + ".c"
        out_path = os.path.join(output_dir, filename)

        # Skip if file already exists
        if os.path.exists(out_path):
            with progress_lock:
                global_progress[0] += 1
                current_count = global_progress[0]
                percent = (current_count / float(total_funcs)) * 100.0
            print("[{:.2f}%][Thread {}] Skipped '{}' (already exists)".format(percent, thread_id, name))
            continue

        results = decomp.decompileFunction(func, max_decompile_time, monitor)

        with progress_lock:
            global_progress[0] += 1
            current_count = global_progress[0]
            percent = (current_count / float(total_funcs)) * 100.0

        if results and results.getDecompiledFunction():
            c_code = results.getDecompiledFunction().getC()
            with open(out_path, "w") as fh:
                fh.write(c_code)
            print("[{:.2f}%][Thread {}] Decompiled '{}' -> '{}'".format(percent, thread_id, name, out_path))
        else:
            print("[{:.2f}%][Thread {}] WARNING: Decompilation failed for '{}'".format(percent, thread_id, name))


# Script
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

program = getCurrentProgram()
fm = program.getFunctionManager()
all_functions = fm.getFunctions(True)

project_m_funcs = [func for func in all_functions if func.getName().startswith(FILTER_NAME)]
total_funcs = len(project_m_funcs)

if total_funcs == 0:
    print("No functions found that start with 'ProjectM'.")
    exit()

print("Found {} functions starting with 'ProjectM'.".format(total_funcs))
print("Using {} threads (batches).".format(NUM_THREADS))

batches = chunkify(project_m_funcs, NUM_THREADS)

global_progress = [0]
progress_lock = threading.Lock()
max_decompile_time = 120  # seconds

threads = []

# Create and start one thread per batch
for thread_id, batch_funcs in enumerate(batches, start=1):
    t = threading.Thread(
        target=decompile_functions_batch,
        args=(thread_id, batch_funcs, program, max_decompile_time,
              OUTPUT_DIR, progress_lock, global_progress, total_funcs)
    )
    threads.append(t)
    t.start()

# Wait for all threads to finish
for t in threads:
    t.join()

print("Decompilation complete. Processed {} functions in total.".format(total_funcs))

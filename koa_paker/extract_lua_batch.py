import struct
import os
import sys

def read_u4(f):
    data = f.read(4)
    if not data:
        return None
    return struct.unpack('<I', data)[0]

def read_len_string(f):
    length = read_u4(f)
    if length is None:
        return None
    return f.read(length).decode('utf-8')

def extract_lua_batch(file_path, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(file_path, 'rb') as f:
        num_entries = read_u4(f)
        if num_entries is None:
            print(f"Failed to read num_entries from {file_path}")
            return

        print(f"Batch {file_path} contains {num_entries} entries.")

        index = []
        for i in range(num_entries):
            res_id = read_u4(f)
            size = read_u4(f)
            index.append({'id': res_id, 'size': size})

        for i in range(num_entries):
            entry_start = f.tell()
            expected_size = index[i]['size']
            
            script_name = read_len_string(f)
            if i < 10:
                print(f"Entry {i}: {script_name}")
            num_hooks = read_u4(f)
            hooks = []
            for h in range(num_hooks):
                hooks.append(read_len_string(f))
            
            bytecode_len = read_u4(f)
            bytecode = f.read(bytecode_len)
            
            # Verify if we read exactly the size specified in the index
            entry_end = f.tell()
            actual_size = entry_end - entry_start
            if actual_size != expected_size:
                 print(f"Warning: Entry {i} (ID: {index[i]['id']}, Name: {script_name}) size mismatch. Expected {expected_size}, got {actual_size}")

            # Safe filename
            safe_name = script_name.replace(':', '_').replace('/', '_').replace('\\', '_')
            if not safe_name:
                safe_name = f"unnamed_{index[i]['id']}"
            
            output_path = os.path.join(output_dir, f"{safe_name}.luac")
            with open(output_path, 'wb') as out_f:
                out_f.write(bytecode)
            
            # Also write some metadata/hooks if needed? 
            # For now just bytecode.
            # print(f"Extracted {script_name} ({bytecode_len} bytes)")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_lua_batch.py <input_batch> <output_dir>")
        sys.exit(1)
    
    extract_lua_batch(sys.argv[1], sys.argv[2])

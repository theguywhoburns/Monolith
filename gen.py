import json

# Load the JSON data from file
with open('syscalls.json') as f:
    data = json.load(f)

# Write syscall declarations to syscalls.h and syscalls.s
with open('syscalls.h', 'w') as f_h, open('syscalls.s', 'w') as f_s:
    for item in data['aaData']:
        syscall_name = item[1]
        if syscall_name == "not implemented": 
            continue
        syscall_arguments = item[2]
        
        # Write to syscalls.h
        syscall_declaration = f"long {syscall_name[:4]}{syscall_arguments};"
        f_h.write(syscall_declaration + "\n")
        
        # Write to syscalls.s
        syscall_declaration_asm = f";{syscall_declaration}\n.global {syscall_name}\n{syscall_name}:\n\tret"
        f_s.write(syscall_declaration_asm + "\n")
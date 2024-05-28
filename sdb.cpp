#include <iostream>
#include <string>
#include <vector>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <iomanip>
#include <map>
#include <sstream>
#include <capstone/capstone.h>
using namespace std;


pid_t child_pid = -1;
string program;
int max_breakpoint_index = 0, breakpoint_num = 0;
uintptr_t hit_breakpoint_address = 0;
bool in_syscall = false;


struct BreakpointInfo {
    uint8_t original_data;
    int index;
};
map<uintptr_t, BreakpointInfo> breakpoints;

void handle_command(const string &command);
void init_debugger(const string &program);
uintptr_t get_entry_point(const string &filename);
void disassemble(uint64_t address);
void step();
void cont();
void info_register();
void set_breakpoint(uintptr_t address);
void delete_breakpoint(int index);
void info_breakpoint();
void check_breakpoint(bool isStep);
void patch(uintptr_t address, uint64_t value, int len);
void system_call();


int main(int argc, char* argv[]) {
    if (argc == 2) {
        program = argv[1];
        init_debugger(program);
    }
    
    string command;
    while (true) {
        cout << "(sdb) ";
        getline(cin, command);
        handle_command(command);
    }
    return 0;
}


void handle_command(const string &command) {
    if (command.substr(0, 4) == "load") {
        if (child_pid != -1) {
            cerr << "A program is already loaded.\n";
            return;
        }
        string program = command.substr(5);
        init_debugger(program);
    } else if (command == "si") {
        if (child_pid == -1) {
            cerr << "** please load a program first.\n";
            return;
        }
        step();
    } else if (command == "cont") {
        if (child_pid == -1) {
            cerr << "** please load a program first.\n";
            return;
        }
        cont();
    } else if (command == "info reg") {
        if (child_pid == -1) {
            cerr << "** please load a program first.\n";
            return;
        }
        info_register();
    } else if (command.substr(0, 5) == "break") {
        if (child_pid == -1) {
            cerr << "** please load a program first.\n";
            return;
        }
        string address_str = command.substr(6);
        if(address_str.substr(0, 2) != "0x") address_str = "0x" + address_str;
        size_t pos;
        uintptr_t address = stoul(address_str, &pos, 16);
        if (pos != address_str.size()) {
            cerr << "Invalid address format.\n" << endl;
            return;
        }
        set_breakpoint(address);
    } else if (command.substr(0, 6) == "delete") {
        if (child_pid == -1) {
            cerr << "** please load a program first.\n";
            return;
        }
        delete_breakpoint(stoi(command.substr(7)));
    } else if (command == "info break") {
        if (child_pid == -1) {
            cerr << "** please load a program first.\n";
            return;
        }
        info_breakpoint();
    } else if (command.substr(0, 5) == "patch") {
        if (child_pid == -1) {
            cerr << "** please load a program first.\n";
            return;
        }

        istringstream iss(command);
        string op;
        uintptr_t address;
        uint64_t value;
        int len;

        iss >> op >> hex >> address >> hex >> value >> dec >> len;
        patch(address, value, len);
    } else if (command == "syscall") {
        if (child_pid == -1) {
            cerr << "** please load a program first.\n";
            return;
        }
        system_call();
    } else {
        cerr << "Unknown command: " << command << "\n";
    }
}


void init_debugger(const string &program) {
    child_pid = fork();

    if (child_pid < 0) cerr << "Failed to fork.\n";
    else if (child_pid == 0) {   // child process
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(program.c_str(), program.c_str(), nullptr);
    } else {    // parent process
        int status;
        if(waitpid(child_pid, &status, 0) < 0) cerr << "wait\n";
        if (WIFEXITED(status)) {
            std::cerr << "Failed to load program.\n";
            child_pid = -1;
            return;
        }
        ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_EXITKILL);

        uintptr_t entry_point = get_entry_point(program);
        if (entry_point == 0) {
            cerr << "Failed to obtain entry point.\n";
            return;
        }
        cout << "** program '" << program << "' loaded. entry point 0x" << hex << entry_point << ".\n";

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        disassemble(regs.rip);
    } 
}


uintptr_t get_entry_point(const string &filename) {
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 0;
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("read");
        close(fd);
        return 0;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        cerr << "Not an ELF file.\n";
        close(fd);
        return 0;
    }

    close(fd);
    return ehdr.e_entry;
}


void disassemble(uint64_t address) {
    // struct user_regs_struct regs;
    // ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    // uint64_t address = regs.rip;
    
    cs_insn *insn;
    size_t count;
    csh handle;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perror("cs_open");
        exit(1);
    }

    // read memory
    uint8_t code[64];
    for (int i = 0; i < 64; ++i) {
        code[i] = ptrace(PTRACE_PEEKTEXT, child_pid, address + i, nullptr);
    }

    // Restore original instruction of breakpoints
    for (int i = 0; i < 64; ++i) {
        if (breakpoints.find(address + i) != breakpoints.end()) {
            code[i] = breakpoints[address + i].original_data;
        }
    }

    count = cs_disasm(handle, code, sizeof(code), address, 0, &insn);
    size_t i = 0;
    if (count > 0) {
        for (i = 0; i < count && i < 5; ++i) {
            cout << "      " << hex << insn[i].address << ": ";
            for (size_t j = 0; j < insn[i].size; ++j) {
                cout << setw(2) << setfill('0') << right << hex << (int)insn[i].bytes[j] << " ";
            }
            int num_spaces = 32 - (insn[i].size * 3);
            cout << string(num_spaces, ' ') << left << setw(10) << setfill(' ') << insn[i].mnemonic << " " << insn[i].op_str << endl;
        }
        cs_free(insn, count);
    } 
    if (i < 5) cout << "** the address is out of the range of the text section." << endl;

    cs_close(&handle);
}


void step() {
    // do step
    ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr);
    int status;
    waitpid(child_pid, &status, 0);

    if (WIFEXITED(status)) {
        cout << "** the target program terminated." << endl;
        child_pid = -1;
        return;
    }
    
    // Reset breakpoint
    if (hit_breakpoint_address != 0) {
        long data = ptrace(PTRACE_PEEKTEXT, child_pid, hit_breakpoint_address, 0);
        long trap = (data & ~0xFF) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, hit_breakpoint_address, trap);
        hit_breakpoint_address = 0;
    }

    check_breakpoint(true);
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    disassemble(regs.rip);
}


void cont() {
    // do continue
    int status;
    ptrace(PTRACE_CONT, child_pid, nullptr, nullptr);
    waitpid(child_pid, &status, 0);
    if (WIFEXITED(status)) {
        cout << "** the target program terminated." << endl;
        child_pid = -1;
    } else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        // Reset breakpoint
        if (hit_breakpoint_address != 0) {
            long data = ptrace(PTRACE_PEEKTEXT, child_pid, hit_breakpoint_address, 0);
            long trap = (data & ~0xFF) | 0xCC;
            ptrace(PTRACE_POKETEXT, child_pid, hit_breakpoint_address, trap);
            hit_breakpoint_address = 0;
        }

        check_breakpoint(false);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        disassemble(regs.rip);
    }
}


void set_breakpoint(uintptr_t address) {
    long data = ptrace(PTRACE_PEEKTEXT, child_pid, address, 0);
    uint8_t original_data = data & 0xFF;
    breakpoints[address] = {original_data, max_breakpoint_index++};
    long trap = (data & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, address, trap);
    breakpoint_num++;
    cout << "** set a breakpoint at 0x" << hex << address << "." << endl;
}


void delete_breakpoint(int index) {
    for (const auto& it : breakpoints) {
        if (it.second.index == index) {
            // restore instruction
            uintptr_t address = it.first;
            long data = ptrace(PTRACE_PEEKTEXT, child_pid, address, 0);
            long restored = (data & ~0xFF) | it.second.original_data;
            ptrace(PTRACE_POKETEXT, child_pid, address, restored);

            breakpoints.erase(it.first);
            breakpoint_num--;
            cout << "** delete breakpoint " << index << ".\n";
            return;
        }
    }
    cout << "** breakpoint " << index << " does not exist.\n";
}



void check_breakpoint(bool isStep) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    uintptr_t address = (!isStep) ? regs.rip - 1 : regs.rip;

    if (breakpoints.find(address) != breakpoints.end()) {
        // restore original instruction
        struct BreakpointInfo bp_info = breakpoints[address];
        long restored = (ptrace(PTRACE_PEEKTEXT, child_pid, address, 0) & ~0xFF) | bp_info.original_data;
        ptrace(PTRACE_POKETEXT, child_pid, address, restored);

        // move rip back
        if (!isStep) {
            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        }

        hit_breakpoint_address = address;
        cout << "** hit a breakpoint at 0x" << hex << address << ".\n";
    }
}


void info_breakpoint() {
    if (breakpoint_num == 0) {
        cout << "** no breakpoints.\n";
        return;
    }
    
    vector<uintptr_t> breakpoints_vec;
    breakpoints_vec.resize(max_breakpoint_index);

    for (const auto& it : breakpoints) {
        breakpoints_vec[it.second.index] = it.first;
    }
    cout << setw(10) << setfill(' ') << "Num" << "Address\n";
    for (int i = 0; i < max_breakpoint_index; i++) {
        if (breakpoints_vec[i]) {
            cout << setw(10) << setfill(' ') << i << hex << "0x" << breakpoints_vec[i] << endl;
        }
    }
}


void patch(uintptr_t address, uint64_t value, int len) {
    if (len != 1 && len != 2 && len != 4 && len != 8) {
        cerr << "Invalid patch length." << endl;
        return;
    }

    long data = ptrace(PTRACE_PEEKTEXT, child_pid, address, 0);
    long mask = (1UL << (len * 8)) - 1;
    value &= mask;

    // patch memory
    data = (data & ~mask) | value;
    ptrace(PTRACE_POKETEXT, child_pid, address, data);
    cout << "** patch memory at address 0x" << hex << address << ".\n";

    // Restore breakpoint
    for(int i = 0; i < len; i++) {
        uintptr_t addr = address + i;
        if (breakpoints.find(addr) != breakpoints.end()) {
            long data = ptrace(PTRACE_PEEKTEXT, child_pid, addr, 0);
            breakpoints[addr].original_data = data & 0xFF;
            long trap = (data & ~0xFF) | 0xCC;
            ptrace(PTRACE_POKETEXT, child_pid, addr, trap);
        }
    }
}


void system_call() {
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    int status;
    waitpid(child_pid, &status, 0);

    if (WIFEXITED(status)) {
        cout << "** the target program terminated." << endl;
        return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    
    if (!in_syscall) {
        // syscall
        if (regs.orig_rax != (unsigned long long)-1) {
            // move rip back (syscall is two words)
            // regs.rip -= 2;
            // ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
            cout << "** enter a syscall(" << dec << regs.orig_rax << ") at 0x" << hex << regs.rip - 2 << ".\n";
            in_syscall = true;
            disassemble(regs.rip - 2);
        } else {
            // check point
            check_breakpoint(false);
            disassemble(regs.rip);
        }
    } 
    else {
        if (regs.orig_rax != (unsigned long long)-1) {
            cout << "** leave a syscall(" << dec << regs.orig_rax << ") = " << dec << regs.rax << " at 0x" << hex << regs.rip - 2 << ".\n";
            in_syscall = false;
            disassemble(regs.rip - 2);
        } else {
            check_breakpoint(false);
            disassemble(regs.rip);
        }
    }
}


void print_register(const string &name, long value) {
    cout << "$" << setw(3) << setfill(' ') << name << " 0x" << setw(16) << setfill('0') << right << hex << value << "    ";
}

void info_register() {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    print_register("rax", regs.rax);
    print_register("rbx", regs.rbx);
    print_register("rcx", regs.rcx);
    cout << endl;
    print_register("rdx", regs.rdx);
    print_register("rsi", regs.rsi);
    print_register("rdi", regs.rdi);
    cout << endl;
    print_register("rbp", regs.rbp);
    print_register("rsp", regs.rsp);
    print_register("r8", regs.r8);
    cout << endl;
    print_register("r9", regs.r9);
    print_register("r10", regs.r10);
    print_register("r11", regs.r11);
    cout << endl;
    print_register("r12", regs.r12);
    print_register("r13", regs.r13);
    print_register("r14", regs.r14);
    cout << endl;
    print_register("r15", regs.r15);
    print_register("rip", regs.rip);
    print_register("eflags", regs.eflags);
    cout << endl;
}

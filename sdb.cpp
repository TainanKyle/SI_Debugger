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
#include <capstone/capstone.h>
using namespace std;

pid_t child_pid = -1;
string program;

void handle_command(const string &command);
void init_debugger(const string &program);
uintptr_t get_entry_point(const string &filename);
void disassemble();
void step();
void cont();
void info_register();


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
            std::cerr << "** please load a program first.\n";
            return;
        }
        step();
    } else if (command == "cont") {
        if (child_pid == -1) {
            std::cerr << "** please load a program first.\n";
            return;
        }
        cont();
    } else if (command == "info reg") {
        if (child_pid == -1) {
            std::cerr << "** please load a program first.\n";
            return;
        }
        info_register();
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

        disassemble();
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


void disassemble() {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    uint64_t address = regs.rip;
    
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

    count = cs_disasm(handle, code, sizeof(code), address, 0, &insn);
    size_t i = 0;
    if (count > 0) {
        for (i = 0; i < count && i < 5; ++i) {
            cout << "      " << hex << insn[i].address << ": ";
            for (size_t j = 0; j < insn[i].size; ++j) {
                cout << setw(2) << setfill('0') << hex << (int)insn[i].bytes[j] << " ";
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
    ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr);
    int status;
    waitpid(child_pid, &status, 0);

    if (WIFEXITED(status)) {
        cout << "** the target program terminated." << endl;
        child_pid = -1;
        return;
    }

    disassemble();
}


void cont() {
    int status;
    ptrace(PTRACE_CONT, child_pid, nullptr, nullptr);
    waitpid(child_pid, &status, 0);
    if (WIFEXITED(status)) {
        cout << "** the target program terminated." << endl;
        child_pid = -1;
    }
}


void print_register(const string &name, long value) {
    cout << "$" << setw(3) << setfill(' ') << name << " 0x" << setw(16) << setfill('0') << hex << value << "    ";
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

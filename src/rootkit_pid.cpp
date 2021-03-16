#include "../include/cpprootcheck.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <stdexcept>
#include <stdlib.h>
#include <array>
#include <string.h>
#include <cstdio>
#include <sys/types.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <algorithm>


namespace cpprootcheck {
    rootkit_pid::rootkit_pid() {
        rootkit_pid::get_pid_max();
        rootkit_pid::verbose = false;
    }

    // public
    int rootkit_pid::hidepid() {
        struct rootkit_pid::PID_INFO PI; 
        std::vector<int> ps_shot = rootkit_pid::pssnapshoot();
        for (int pid = 0; pid < rootkit_pid::max_pid; ++pid ) {    
            if (rootkit_pid::pid_alive(pid) && rootkit_pid::pid_DIRexist(pid) && !(std::find(ps_shot.begin(), ps_shot.end(),pid)!=ps_shot.end())) {
                if (rootkit_pid::verbose) {
                    std::cout
                    << "[ rootkit_pid ] Detected on pid "  
                    << pid 
                    << std::endl
                    << "\t\tCMDLINE->\t"
                    << rootkit_pid::pid_cmdline(pid)
                    << std::endl;
                } 
                PI = {
                    .cmdline    =   rootkit_pid::pid_cmdline(pid),
                    .pid        =   pid
                };
                rootkit_pid::PIDS.push_back(PI);
            }
        }
        return 0; 
    }

    // private
    void rootkit_pid::get_pid_max() {
        std::fstream r;
        const char *PID_FILE = PID_FILE_MAX;
        r.open(PID_FILE, std::ios::in);
        if (!r) {
            throw std::runtime_error("ERROR: Can't read MAX_PID file");
        }
        std::string max_pid;
        getline(r, max_pid); // possible race condition here 
        r.close();
        rootkit_pid::max_pid = std::stoi(max_pid);
    }

    std::vector<int> rootkit_pid::pssnapshoot() {
        // ps --no-header -eL o lwp
        // pseudostackoverflow block
        const char* command = "ps --no-header -eL o lwp"; 
        std::vector<int> ret;
        std::array<char, 128> buffer;
        std::string output;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command, "r"), pclose);
        if (!pipe) {
            throw std::runtime_error("ERROR: ps snapshoot error during command execution");
        }
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr ) {
            ret.push_back(std::stoi(buffer.data()));
        }
        return ret;
    }

    bool rootkit_pid::pid_alive(int pid) {
        if (kill((pid_t) pid, 0) == 0) {
            return true;
        }
        return false;
    }

    bool rootkit_pid::pid_DIRexist(int pid) {
        // maybe boost or <filesystem> is more fasters 
        struct stat info;
        std::string pathname = "/proc/" + std::to_string(pid);
        if (stat (pathname.c_str(), &info) == 0) {
            return true;
        }
        return false; 
    }

    std::string rootkit_pid::pid_cmdline(int pid) {
        std::string pathname = "/proc/" + std::to_string(pid) + "/cmdline";
        std::fstream r;
        r.open(pathname, std::ios::in);
        if (!r) {
            return (std::string)"Failed open cmdline\t\t:(";
        }
        std::string cmdline;
        getline(r, cmdline); // possible race condition here 
        r.close();
        return cmdline;
    }
}
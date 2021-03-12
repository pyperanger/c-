#pragma once 
#include <iostream>
#include <vector>

#ifndef PID_FILE_MAX
    #define PID_FILE_MAX "/proc/sys/kernel/pid_max"
#endif
        
namespace cpprootcheck {
    // Global namespace vars
    class rootkit_pid {
        public:
            struct PID_INFO {
                std::string cmdline;
                pid_t       pid;
                // append with more pid information if needed
            };
            // To user export malicius PID info
            std::vector<PID_INFO> PIDS;
            bool    verbose;            
            int     max_pid;            
            int     hidepid();
            rootkit_pid();
        private:
            void                get_pid_max();
            std::vector<int>    pssnapshoot();
            int                 pid_alive(int);
            bool                pid_DIRexist(int); 
            std::string         pid_cmdline(int);
    };
}


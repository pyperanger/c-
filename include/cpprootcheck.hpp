#pragma once 
#include "rootkit_pid.hpp"

#include <iostream>
#include <vector>

#ifndef PID_FILE_MAX
    #define PID_FILE_MAX "/proc/sys/kernel/pid_max"
#endif
        
namespace cpprootcheck {
    // Global
    class cpprootcheck {};
}


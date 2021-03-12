#include "include/cpprootcheck.hpp"
#include <iostream>

int main(void)
{
    cpprootcheck::rootkit_pid rk;
    rk.hidepid();
    rk.verbose = true; 
    for (auto p : rk.PIDS) {
        std::cout << p.pid << "\t" << p.cmdline << std::endl;  
    } 
    return 0;
}
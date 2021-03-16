#include "include/cpprootcheck.hpp"
#include <iostream>

int main(void)
{
    cpprootcheck::rootkit_pid rk;
    rk.verbose = true; 
    rk.hidepid();
    for (auto p : rk.PIDS) {
        std::cout << p.pid << "\t" << p.cmdline << std::endl;  
    } 
    //u can
    //std::vector<cpprootcheck::rootkit_pid::PID_INFO> my_malicius_pids = rk.PIDS();
    return 0;
}
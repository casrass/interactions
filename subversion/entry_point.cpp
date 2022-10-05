
#include "sdk/sdk.hpp"

auto main() -> __int32
{
    if (sdk::check_virtual_machine())
    {
        std::cout << "flag - virtual_machine" << std::endl;
    }

    sdk::patch_remote_breakin();

    sdk::patch_break_point();

    for (;; Sleep(1000))
    {
        if (sdk::check_being_debugged())
            std::cout << "flag - being_debugged" << std::endl;

        if (sdk::check_is_debugger_present())
            std::cout << "flag - is_debugger_present" << std::endl;

        if (sdk::check_thread_context())
            std::cout << "flag - thread_context" << std::endl;

        if (sdk::check_working_set())
            std::cout << "flag - working_set" << std::endl;
    }

    return std::cin.get() != 0xffffffff;
}

#include "memory/memory.hpp"

namespace sdk
{
	extern auto check_being_debugged() -> bool;

	extern auto check_virtual_machine() -> bool;

	extern auto patch_break_point() -> void;

	extern auto check_is_debugger_present() -> bool;

	extern auto check_working_set() -> bool;

	extern auto check_thread_context() -> bool;

	extern auto patch_remote_breakin() -> void;
}
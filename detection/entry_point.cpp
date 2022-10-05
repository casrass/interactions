
#include "sdk/sdk.hpp"

auto main() -> __int32
{
	auto target_pid = sdk::memory::get_process_id("subversion.exe");

	if (target_pid == 0)
	{
		std::cout << "target process not running" << std::cin.get();
		return 0;
	}

	void* handle = nullptr;

	sdk::memory::nt_open_process(&handle, PROCESS_ALL_ACCESS, target_pid);

	auto exe_base = sdk::memory::get_remote_library_base(handle, "subversion.exe");

	sdk::patch_being_debugged(handle, sdk::memory::get_remote_p_env(handle));

	return std::cin.get() != 0xffffffff;
} 
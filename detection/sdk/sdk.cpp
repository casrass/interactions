
#include "sdk.hpp"

auto sdk::patch_being_debugged(void* handle, _PEB* p_env) -> void
{
	auto is_being_debugged = false;

	sdk::memory::nt_write_virtual_memory(handle, (void*)((unsigned __int64)p_env + 0x2), &is_being_debugged, 1, nullptr);
}
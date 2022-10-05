
#include "sdk.hpp"

auto sdk::check_being_debugged() -> bool
{
	return sdk::memory::get_p_env()->BeingDebugged;
}

auto sdk::check_virtual_machine() -> bool
{
	static const auto get_itd_base = [&]() -> unsigned __int64
	{
		std::string idt_buf(6, 0);

		__sidt(&idt_buf[0]);

		return *(unsigned __int64*)&idt_buf[2];
	};

	static const auto get_gdt_base = [&]() -> unsigned __int64
	{
		std::string gdt_buf(6, 0);

		_sgdt(&gdt_buf[0]);

		return *(unsigned __int64*)&gdt_buf[2];
	};

	return get_itd_base() >> 24 == 0xff || get_gdt_base() >> 24 == 0xff;
}

auto sdk::patch_break_point() -> void
{
	static const auto dbg_break_point = sdk::memory::get_proc_address(sdk::memory::get_ntdll(), "DbgBreakPoint");

	unsigned long old_protect = 0;

	sdk::memory::nt_protect_virtual_memory((void*)-1, (void*)dbg_break_point, 1, PAGE_EXECUTE_READWRITE, &old_protect);

	*(unsigned char*)dbg_break_point = (unsigned char)0xc3 /*put a return byte on the start of the bp fn*/;
}

auto sdk::check_is_debugger_present() -> bool
{
	static const auto is_debugger_present = sdk::memory::get_proc_address(
		sdk::memory::get_library_base("kernel32.dll"), "DbgBreakPoint");

	bool present = false;

	for (auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); snap != INVALID_HANDLE_VALUE; Sleep(1))
	{
		tagPROCESSENTRY32 entry
		{
			sizeof(tagPROCESSENTRY32)
		};

		for (auto init = Process32First(snap, &entry); init && Process32Next(snap, &entry) && !present; Sleep(1))
		{
			if (GetCurrentProcessId() == entry.th32ProcessID)
				continue;

			void* handle = nullptr;

			sdk::memory::nt_open_process(&handle, PROCESS_ALL_ACCESS, entry.th32ProcessID);

			unsigned long fn_data = 0;

			sdk::memory::nt_read_virtual_memory(handle, (void*)is_debugger_present, &fn_data, 4, nullptr);

			if (fn_data != *(unsigned long*)is_debugger_present)
			{
				present = true;
			}

			sdk::memory::nt_close(handle);
		}
	}

	return present;
}

auto sdk::check_working_set() -> bool
{
	static const auto query_working_set = sdk::memory::get_proc_address(
		sdk::memory::get_library_base("kernel32.dll"), "K32QueryWorkingSet");

	static void* region = nullptr;

	static unsigned __int64 size = 0x1000;

	static auto alloc = sdk::memory::nt_allocate_virtual_memory(
		(void*)-1, &region, nullptr, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	_PSAPI_WORKING_SET_EX_INFORMATION working_set_info
	{
		(void*)alloc
	};

	((bool(_stdcall*)(void*, void*, unsigned long))query_working_set)
		((void*)-1, &working_set_info, sizeof(working_set_info));

	return working_set_info.VirtualAttributes.Valid & 0x1;
}

auto sdk::check_thread_context() -> bool
{
	static const auto get_thread_context = sdk::memory::get_proc_address(
		sdk::memory::get_library_base("kernel32.dll"), "Wow64GetThreadContext");

	_CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	((bool(_stdcall*)(void*, void*))get_thread_context)
		((void*)-1, &ctx);

	return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

auto sdk::patch_remote_breakin() -> void
{
	static auto dbg_ui_remote_breakin = sdk::memory::get_proc_address(sdk::memory::get_library_base("ntdll.dll"), "DbgUiRemoteBreakin");

	static auto terminate_process = sdk::memory::get_proc_address(sdk::memory::get_library_base("ntdll.dll"), "NtTerminateProcess");

	std::string shellcode
	{
		(char)0x6a, 0x00, /*push 0x0*/
		0x68, (char)0xff, /*push 0xffffffffffffffff*/
		(char)0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*mov rax terminate_process*/
		(char)0xff, (char)0xd0 /*call rax*/
	};

	*(unsigned __int64*)&shellcode[8] = terminate_process;

	unsigned long old_protect = 0;

	sdk::memory::nt_protect_virtual_memory((void*)-1, (void*)dbg_ui_remote_breakin, shellcode.size(), PAGE_READWRITE, &old_protect);

	for (unsigned __int64 x = 0; x < shellcode.size(); ++x)
	{
		*(char*)(dbg_ui_remote_breakin + x) = shellcode[x];
	}

	sdk::memory::nt_protect_virtual_memory((void*)-1, (void*)dbg_ui_remote_breakin, shellcode.size(), old_protect, &old_protect);
}
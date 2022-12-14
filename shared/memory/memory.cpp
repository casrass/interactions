
#include "memory.hpp"

auto sdk::memory::get_p_env() -> _PEB*
{
	return ((_TEB*)__readgsqword(offsetof(_NT_TIB, Self)))->ProcessEnvironmentBlock /*current process enviroment block pointer*/;
}

auto sdk::memory::get_ntdll() -> unsigned __int64
{
	static const auto get_ntdll_dll = []() -> unsigned __int64
	{
		auto p = sdk::memory::get_p_env();

		auto base = (void*)nullptr;

		for (auto entry = p->Ldr->InMemoryOrderModuleList; entry.Flink != &p->Ldr->InMemoryOrderModuleList; entry = *entry.Flink)
		{
			auto module_entry = (_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(entry.Flink, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (module_entry->DllBase > base)
			{
				base = module_entry->DllBase;
			}
		}

		std::cout << "ntdll.dll - 0x" << std::hex << base << std::endl;

		return (unsigned __int64)base /*the last loaded module in memory is ntdll -> we get biggest base address from the list*/;
	};

	static const auto ntdll_dll = get_ntdll_dll();

	return ntdll_dll;
}

auto sdk::memory::get_library_base(const char* mod_name) -> unsigned __int64
{
	auto p = sdk::memory::get_p_env();

	if (mod_name != nullptr)
	{
		unsigned __int64 name_length = 1;

		for (auto base = (unsigned __int64)&mod_name[0]; *(char*)base != 0; ++name_length, ++base /*calculate the name length*/);

		for (auto entry = p->Ldr->InMemoryOrderModuleList; entry.Flink != &p->Ldr->InMemoryOrderModuleList; entry = *entry.Flink)
		{
			auto module_entry = (_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(entry.Flink, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			unsigned __int64 of = 0;

			for (unsigned __int64 base =
				(unsigned __int64)&module_entry->FullDllName.Buffer[0] + 2, x = 2; *(char*)base != 0; base += 2, x += 2 /*path*/)
			{
				if (*(char*)base == '\\' /*find the offset of the last separator in order to get the mod name without the path*/)
				{
					of = x;
				}
			}

			for (unsigned __int64 base =
				(unsigned __int64)&module_entry->FullDllName.Buffer[0] + of + 2, x = 0; x < name_length; ++x, base += 2 /*name*/)
			{
				static const auto to_upper = [](char x) -> char
				{
					char upper = x;

					if (x >= 'a' && x <= 'z')
					{
						upper -= 32;
					}

					return upper;
				};

				if (to_upper(*(char*)(mod_name + x)) != to_upper(*(char*)base) /*verify if the current name matches the passed*/)
				{
					break;
				}

				if (x == name_length - 1 && *(char*)base == 0)
				{
					return (unsigned __int64)module_entry->DllBase;
				}
			}
		}
	}

	return 0;
}

auto sdk::memory::get_remote_library_base(void* handle, const char* mod_name) -> unsigned __int64
{
	auto p_addr = sdk::memory::get_remote_p_env(handle);

	if (mod_name != nullptr)
	{
		unsigned __int64 name_length = 1;

		for (auto base = (unsigned __int64)&mod_name[0]; *(char*)base != 0; ++name_length, ++base /*calculate the name length*/);

		unsigned __int64 ldr = 0;

		sdk::memory::nt_read_virtual_memory(handle, (void*)((unsigned __int64)p_addr + 0x18), &ldr, 8, nullptr);

		unsigned __int64 base = 0;

		sdk::memory::nt_read_virtual_memory(handle, (void*)(ldr + 0x20), &base, 8, nullptr);

		for (unsigned __int64 entry = base; base != 0;)
		{
			unsigned short size = 0;

			sdk::memory::nt_read_virtual_memory(handle, (void*)(entry + 0x38), &size, 2, nullptr);

			unsigned __int64 ptr = 0;

			sdk::memory::nt_read_virtual_memory(handle, (void*)(entry + 0x40), &ptr, 8, nullptr);

			std::string buffer(255, 0);
			
			sdk::memory::nt_read_virtual_memory(handle, (void*)ptr, &buffer[0], size, nullptr);

			buffer.resize(size);

			unsigned __int64 of = 0;

			for (unsigned __int64 base =	
				(unsigned __int64)&buffer[0] + 2, x = 2; *(char*)base != 0; base += 2, x += 2 /*path*/)
			{
				if (*(char*)base == '\\' /*find the offset of the last separator in order to get the mod name without the path*/)
				{
					of = x;
				}
			}

			for (unsigned __int64 base =
				(unsigned __int64)&buffer[0] + of + 2, x = 0; x < name_length; ++x, base += 2 /*name*/)
			{
				static const auto to_upper = [](char x) -> char
				{
					char upper = x;

					if (x >= 'a' && x <= 'z')
					{
						upper -= 32;
					}

					return upper;
				};

				if (to_upper(*(char*)(mod_name + x)) != to_upper(*(char*)base) /*verify if the current name matches the passed*/)
				{
					break;
				}

				if (x == name_length - 1 && *(char*)base == 0)
				{
					unsigned __int64 mod_base = 0;

					sdk::memory::nt_read_virtual_memory(handle, (void*)(entry + 0x20), &mod_base, 8, nullptr);

					return mod_base;
				}
			}

			sdk::memory::nt_read_virtual_memory(handle, (void*)entry, &entry, 8, nullptr);

			if (base == entry)
			{
				break;
			}
		}
	}

	return 0;
}

auto sdk::memory::get_proc_address(unsigned __int64 mod, const char* exp_name) -> unsigned __int64
{
	if (mod != 0)
	{
		unsigned __int64 name_length = 1;

		for (auto base = (unsigned __int64)&exp_name[0]; *(char*)base != 0; ++name_length, ++base /*calculate the name length*/);

		auto dos_header = (_IMAGE_DOS_HEADER*)mod;

		auto nt_headers = (_IMAGE_NT_HEADERS64*)((unsigned char*)dos_header + dos_header->e_lfanew);

		if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		{
			return 0;
		}

		auto export_directory = (_IMAGE_EXPORT_DIRECTORY*)((unsigned char*)
			dos_header + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress /*ex directory*/);

		auto offsets = (unsigned __int32*)((unsigned char*)dos_header + export_directory->AddressOfFunctions);

		auto names = (unsigned __int32*)((unsigned char*)dos_header + export_directory->AddressOfNames);

		auto ordinals = (unsigned __int16*)((unsigned char*)dos_header + export_directory->AddressOfNameOrdinals);

		for (unsigned __int32 x = 0; x < export_directory->NumberOfFunctions; ++x)
		{
			for (unsigned __int64 y = 0; y < name_length; ++y)
			{
				if (*(char*)(exp_name + y) != *(char*)((unsigned char*)dos_header + names[x] + y))
				{
					break;
				}

				if (y == name_length - 1 && *(char*)((unsigned char*)dos_header + names[x] + y) == 0)
				{
					return mod + offsets[ordinals[x]] /*return the function address using the module base address and ordinals*/;
				}
			}
		}
	}

	return 0;
}

auto sdk::memory::nt_open_process(
	void** handle,
	unsigned long access,
	unsigned long pid
) -> long
{
	static const auto proc_address = sdk::memory::get_proc_address(sdk::memory::get_ntdll(),
		"NtOpenProcess");

	_OBJECT_ATTRIBUTES object_attributes
	{
		sizeof(_OBJECT_ATTRIBUTES)
	};

	_CLIENT_ID client_id
	{
		(void*)pid
	};

	return ((long(_stdcall*)(void**, unsigned long, _OBJECT_ATTRIBUTES*, _CLIENT_ID*))proc_address)
		(handle, access, &object_attributes, &client_id);
}

auto sdk::memory::nt_close(
	void* handle
) -> long
{
	static const auto proc_address = sdk::memory::get_proc_address(sdk::memory::get_ntdll(),
		"NtClose");

	return ((long(_stdcall*)(void*))proc_address)
		(handle);
}

auto sdk::memory::nt_query_virtual_memory(
	void* handle,
	void* address,
	unsigned char mode,
	void* mbi,
	unsigned __int64 size,
	unsigned __int64* bytes_read
) -> long
{
	static const auto proc_address = sdk::memory::get_proc_address(sdk::memory::get_ntdll(),
		"NtQueryVirtualMemory");

	return ((long(_stdcall*)(void*, void*, unsigned char, void*, unsigned __int64, unsigned __int64*))proc_address)
		(handle, address, mode, mbi, size, bytes_read);
}

auto sdk::memory::nt_read_virtual_memory(
	void* handle,
	void* address,
	void* buffer,
	unsigned __int64 size,
	unsigned __int64* bytes_read
) -> long
{
	static const auto proc_address = sdk::memory::get_proc_address(sdk::memory::get_ntdll(),
		"NtReadVirtualMemory");

	return ((long(_stdcall*)(void*, void*, void*, unsigned __int64, unsigned __int64*))proc_address)
		(handle, address, buffer, size, bytes_read);
}

auto sdk::memory::nt_write_virtual_memory(
	void* handle,
	void* address,
	void* buffer,
	unsigned __int64 size,
	unsigned __int64* bytes_written
) -> long
{
	static const auto proc_address = sdk::memory::get_proc_address(sdk::memory::get_ntdll(),
		"NtWriteVirtualMemory");

	return ((long(_stdcall*)(void*, void*, void*, unsigned __int64, unsigned __int64*))proc_address)
		(handle, address, buffer, size, bytes_written);
}

auto sdk::memory::nt_allocate_virtual_memory(
	void* handle,
	void** address,
	unsigned __int64* zero_bits,
	unsigned __int64* size,
	unsigned __int64 type,
	unsigned __int64 protection
) -> long
{
	static const auto proc_address = sdk::memory::get_proc_address(sdk::memory::get_ntdll(),
		"NtAllocateVirtualMemory");

	return ((long(_stdcall*)(void*, void**, unsigned __int64*, unsigned __int64*, unsigned __int64, unsigned __int64))proc_address)
		(handle, address, zero_bits, size, type, protection);
}

auto sdk::memory::nt_query_information_process(
	void* handle,
	unsigned char mode,
	void* pqi,
	unsigned __int64 size,
	unsigned __int64* bytes_read
) -> long
{
	static const auto proc_address = sdk::memory::get_proc_address(sdk::memory::get_ntdll(),
		"NtQueryInformationProcess");

	return ((long(_stdcall*)(void*, unsigned char, void*, unsigned __int64, unsigned __int64*))proc_address)
		(handle, mode, pqi, size, bytes_read);
}

auto sdk::memory::nt_protect_virtual_memory(
	void* handle,
	void* address,
	unsigned __int64 size,
	unsigned long new_protection,
	unsigned long* old_protection
) -> long
{
	static const auto proc_address = sdk::memory::get_proc_address(sdk::memory::get_ntdll(),
		"NtProtectVirtualMemory");

	return ((long(_stdcall*)(void*, void**, unsigned __int64*, unsigned long, unsigned long*))proc_address)
		(handle, &address, &size, new_protection, old_protection);
}
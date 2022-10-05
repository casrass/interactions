
#include "../hdr.hpp"

namespace sdk::memory
{
	extern __forceinline auto get_p_env() -> _PEB*;

	extern __forceinline auto get_ntdll() -> unsigned __int64;

	extern __forceinline auto get_library_base(const char* mod_name) -> unsigned __int64;

	extern __forceinline auto get_remote_library_base(void* handle, const char* mod_name) -> unsigned __int64;

	extern __forceinline auto get_proc_address(unsigned __int64 mod, const char* exp_name) -> unsigned __int64;
}

namespace sdk::memory
{
	extern __forceinline auto nt_open_process(
		void** handle,
		unsigned long access,
		unsigned long pid
	) -> long;

	extern __forceinline auto nt_close(
		void* handle
	) -> long;

	extern __forceinline auto nt_query_virtual_memory(
		void* handle,
		void* address,
		unsigned char mode,
		void* mbi,
		unsigned __int64 size,
		unsigned __int64* bytes_read
	) -> long;

	extern __forceinline auto nt_read_virtual_memory(
		void* handle,
		void* address,
		void* buffer,
		unsigned __int64 size,
		unsigned __int64* bytes_read
	) -> long;

	extern __forceinline auto nt_write_virtual_memory(
		void* handle,
		void* address,
		void* buffer,
		unsigned __int64 size,
		unsigned __int64* bytes_written
	) -> long;

	extern __forceinline auto nt_allocate_virtual_memory(
		void* handle,
		void** address,
		unsigned __int64* zero_bits,
		unsigned __int64* size,
		unsigned __int64 type,
		unsigned __int64 protection
	) -> long;

	extern __forceinline auto nt_query_information_process(
		void* handle,
		unsigned char mode,
		void* pqi,
		unsigned __int64 size,
		unsigned __int64* bytes_read
	) -> long;

	extern __forceinline auto nt_protect_virtual_memory(
		void* handle,
		void* address,
		unsigned __int64 size,
		unsigned long new_protection,
		unsigned long* old_protection
	) -> long;
}

namespace sdk::memory
{
	extern __forceinline auto get_process_id(const char* exe_name) -> unsigned long
	{
		unsigned long process_id = 0;

		if (exe_name != nullptr)
		{
			auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (snap != INVALID_HANDLE_VALUE)
			{
				tagPROCESSENTRY32 entry
				{
					sizeof(tagPROCESSENTRY32)
				};

				for (auto init = Process32First(snap, &entry); init && Process32Next(snap, &entry);)
				{
					if (std::string(entry.szExeFile).find(exe_name) != std::string::npos)
					{
						process_id = entry.th32ProcessID;
					}
				}

				sdk::memory::nt_close(snap);
			}
		}

		return process_id;
	}

	extern __forceinline auto get_remote_p_env(void* handle) -> _PEB*
	{
		_PROCESS_BASIC_INFORMATION pbi;

		sdk::memory::nt_query_information_process(handle, 0, &pbi, sizeof(pbi), nullptr);

		return pbi.PebBaseAddress;
	}

	/*extern __forceinline auto get_remote_symbols(void* handle, unsigned __int64 image_base) -> std::vector<unsigned __int64>
	{
		std::cout << "exe base - 0x" << std::hex << image_base << std::endl;

		unsigned __int32 hdr = 0;

		sdk::memory::nt_read_virtual_memory(handle, (void*)(image_base + 0x3c), &hdr, 4, nullptr);

		unsigned __int32 sym_tbl_ptr = 0;

		_IMAGE_NT_HEADERS64

		sdk::memory::nt_read_virtual_memory(handle, (void*)(image_base + hdr), &sym_tbl_ptr, 4, nullptr);

		std::cout << "sym table ptr - 0x" << std::hex << (image_base + hdr) << std::endl;

		return { 0 };
	}*/
}
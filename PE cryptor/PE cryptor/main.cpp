#include <map>
#include <iostream>
#include <fstream>
#include <windows.h>
#include <vector>
#include "PE.h"
#include "CLI11.hpp"

#define uint unsigned int
using namespace std;

class PE_cryptor
{
public:
	PE_cryptor(const string& input_fname)
		: pe(input_fname)
	{
		memset(&new_section_header, 0, sizeof(IMAGE_SECTION_HEADER));
		has_reloc = (bool)pe.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	}

	void encrypt(const string& output_fname)
	{
		calculate_virtual_address();
		vector<uint> offsets = generate_shellcode();
		init_new_section();
		PE::Section new_section(&new_section_header, shellcode);
		new_section.contains_in_data_directory = true;
		pe.add_section(new_section);
		edit_reloc_table(offsets);

		encrypt_sections();

		pe.optional_header->AddressOfEntryPoint = new_section_header.VirtualAddress;

		pe.save(output_fname);
	}

	vector<uint> generate_shellcode()
	{
		vector<uint> addrs, offsets{ 1, 7, 12 };
		parse_reloc_table(addrs);

		char shellcode_start[] = "\x68\xEF\xBE\xAD\xDE\x60\x68\xBE\xBA\xFE\xCA\xBE\x00\x00\x00\x00\x6A\xFF";
		char shellcode_end[] = "\x58\x83\xF8\xFF\x74\x11\x5B\xB9\x00\x00\x00\x00\x80\x34\x08\xFF\x41\x39\xD9\x75\xF7\xEB\xE9\x58\x8B\x18\x83\xFB\xFF\x74\x09\x01\xF3\x01\x33\x83\xC0\x04\xEB\xF0\x61\xC3";

		uint shellcode_size = sizeof(shellcode_start) + sizeof(shellcode_end) + pe.sections.size() * 10 - 2;
		uint shellcode_and_data_size = shellcode_size + addrs.size() * 4;

		uint aligned_size = PE::align(shellcode_and_data_size, pe.optional_header->FileAlignment);
		
		shellcode_section_size = aligned_size;
		shellcode = (char*)malloc(aligned_size);
		memset(shellcode, 0, aligned_size);

		memcpy(shellcode, shellcode_start, sizeof(shellcode_start)-1);

		uint offset = sizeof(shellcode_start)-1;
		for (auto& section : pe.sections)
		{
			if (section.contains_in_data_directory)
				continue;
			write_push(shellcode, section.header->SizeOfRawData, offset);
			write_push(shellcode, pe.optional_header->ImageBase + section.header->VirtualAddress, offset + 5);
			offsets.push_back(offset + 6);
			offset += 10;
		}

		memcpy(shellcode + offset, shellcode_end, sizeof(shellcode_end)-1);
		uint addr_offset = offset + sizeof(shellcode_end) - 1;
		*(uint*)(shellcode + 1) = pe.optional_header->ImageBase + pe.optional_header->AddressOfEntryPoint;
		*(uint*)(shellcode + 7) = pe.optional_header->ImageBase + new_section_header.VirtualAddress + addr_offset;
		
		for (auto addr : addrs)
		{
			*(uint*)(shellcode + addr_offset) = addr;
			addr_offset += 4;
		}
		return offsets;
	}
	void edit_reloc_table(vector<uint>& offsets) {
		if (!has_reloc)
			return;

		uint factical_reloc_size = PE::align(sizeof(IMAGE_BASE_RELOCATION) + offsets.size() * 2, 4);
		uint reloc_section_size = PE::align(factical_reloc_size, pe.optional_header->FileAlignment);

		PE::Section reloc_section = *find_if(pe.sections.begin(), pe.sections.end(), [this](PE::Section &section) {
			return section.header->VirtualAddress == pe.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		});

		pe.resize_section(reloc_section, reloc_section_size);

		reloc_section = *find_if(pe.sections.begin(), pe.sections.end(), [this](PE::Section& section) {
			return section.header->VirtualAddress == pe.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		}); // Гавнокод

		pe.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = factical_reloc_size;
		memset(reloc_section.data, 0, reloc_section_size);

		IMAGE_BASE_RELOCATION* reloc_entry = (IMAGE_BASE_RELOCATION*)reloc_section.data;
		reloc_entry->SizeOfBlock = factical_reloc_size;
		reloc_entry->VirtualAddress = new_section_header.VirtualAddress;
		WORD* blocks = at_offset(reloc_section.data, sizeof(IMAGE_BASE_RELOCATION), WORD);
		for (uint i = 0; i < offsets.size(); i++)
			blocks[i] = (IMAGE_REL_BASED_HIGHLOW << 12) | (offsets[i] & 0xfff);
	}


	void parse_reloc_table(vector<uint> &addrs)
	{
		if (!has_reloc)
			return;

		uint reloc_size = pe.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, offset = 0;
		while (1)
		{
			if (offset >= reloc_size)
				break;
			PE::Section reloc_section = *find_if(pe.sections.begin(), pe.sections.end(), [this](PE::Section& section) {
				return section.header->VirtualAddress == pe.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
			});
			IMAGE_BASE_RELOCATION* relocation = at_offset(reloc_section.data, offset, IMAGE_BASE_RELOCATION);
			WORD* reloc_offsets = at_offset(relocation, sizeof(IMAGE_BASE_RELOCATION), WORD);
			uint offsets_count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			for (uint i = 0; i < offsets_count; i++)
			{
				WORD reloc_entry = reloc_offsets[i];
				if ((reloc_entry >> 12) != IMAGE_REL_BASED_HIGHLOW)
					continue;
				reloc_entry &= 0xfff;
				addrs.push_back(reloc_entry + relocation->VirtualAddress + pe.optional_header->ImageBase);
			}
			offset += relocation->SizeOfBlock;
		}
		addrs.push_back(0xffffffff);
	}

	void encrypt_sections()
	{
		for (auto section : pe.sections)
		{
			if (section.contains_in_data_directory || section.header->VirtualAddress == new_section_header.VirtualAddress)
				break;
			char* data = section.data;
			uint size = section.header->SizeOfRawData;
			for (uint i = 0; i < size; i++)
				data[i] ^= 0xff;
			section.header->Characteristics |= IMAGE_SCN_MEM_WRITE;
		}
	}

	void init_new_section() 
	{
		PE::Section& last_section = pe.sections[pe.sections.size() - 1];
		uint pointer_to_raw_data = last_section.header->PointerToRawData + last_section.header->SizeOfRawData;
		
		new_section_header.PointerToRawData = PE::align(pointer_to_raw_data, pe.optional_header->FileAlignment);

		memcpy((char*)&new_section_header.Name, ".centry\x00", 8);
		new_section_header.SizeOfRawData = shellcode_section_size;
		new_section_header.Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;
		new_section_header.Misc.VirtualSize = PE::align(shellcode_section_size, pe.optional_header->SectionAlignment);
	}

	void calculate_virtual_address() {
		vector<PE::Section*> sections_sorted_by_addr;
		for (auto section : pe.sections)
			sections_sorted_by_addr.push_back(&section);
		sort(sections_sorted_by_addr.begin(), sections_sorted_by_addr.end(), [](PE::Section* s1, PE::Section* s2) {
			return s1->header->VirtualAddress < s2->header->VirtualAddress;
			});
		PE::Section& last_section1 = *sections_sorted_by_addr[sections_sorted_by_addr.size() - 1];
		uint virtual_address = last_section1.header->VirtualAddress + last_section1.header->Misc.VirtualSize;
		new_section_header.VirtualAddress = PE::align(virtual_address, pe.optional_header->SectionAlignment);
	}

	void write_push(char* s, uint val, uint offset)
	{
		s[offset] = 0x68;
		memcpy(s + offset + 1, &val, 4);
	}

private:
	PE pe;
	IMAGE_SECTION_HEADER new_section_header;
	uint shellcode_section_size = 0;
	char* shellcode;
	bool has_reloc = true;
};


int main(int argc, char** argv)
{
	CLI::App app{ "Simple PE cryptor" };
	std::string input = "", output;
	app.add_option("-f,--file", input, "Input file")->required(true);
	app.add_option("-o,--output", output, "Output file")->required(true);

	CLI11_PARSE(app, argc, argv);

	try {
		PE_cryptor cryptor(input);
		cryptor.encrypt(output);
	}
	catch (exception &e) {
		cout << e.what() << endl;
		return -1;
	}
	cout << "PE encrypted successfully." << endl;
	return 0;
}
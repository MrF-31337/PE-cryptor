#include "pefile.hpp"

#define uint unsigned int
#define makeRWX(x) x.Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
#define check(x) strcmp((char *)header.Name, x)  

uint align(uint n, uint alignment)
{
	uint a = (n / alignment)*alignment;
	return n % alignment ? a + alignment : a;
}

void writePush(char *s, uint val, uint offset)
{
	s[offset] = 0x68;
	memcpy(s+offset+1, &val, 4);
}


int main(int argc, char **argv) 
{
	if (argc != 3)
	{
		printf("Usage:\n\t %s input.exe output.exe\n", argv[0]);
		exit(0);
	}
	//ifstream f("C:\\Users\\mrfac\\Documents\\ncat.exe", ios::binary);
	//ofstream f1("C:\\Users\\mrfac\\Documents\\ncat_packed.exe", ios::binary);
	ifstream f(argv[1], ios::binary);
	ofstream f1(argv[2], ios::binary);
	pefile pe(&f);
	IMAGE_SECTION_HEADER *last_section_header, *code_section = NULL;
	char *code = NULL;
	uint entrypoint = pe.pe_headers.OptionalHeader.AddressOfEntryPoint;
	uint addr = 0;
	uint image_base = pe.pe_headers.OptionalHeader.ImageBase;

	int idx = 0;
	for (size_t i = 0; i < pe.sections.size(); i++)
	{
		if (pe.sections[i].header.VirtualAddress > addr)
		{
			addr = pe.sections[i].header.VirtualAddress;
			idx = i;
		}
		int tmp = (entrypoint - pe.sections[i].header.VirtualAddress);
		if (tmp > 0 && tmp < pe.sections[i].header.Misc.VirtualSize)
		{
			code_section = &pe.sections[i].header;
			code = pe.sections[i].data;
		}
	}
	last_section_header = &pe.sections[idx].header;
	printf("Last (%d) section is %s, size = %d\n", idx, last_section_header->Name, last_section_header->SizeOfRawData);

	printf("Entrypoint: %p\n", entrypoint);
	printf("%s at %p\n", code_section->Name, code_section->VirtualAddress);
	printf("%s size = %d\n", code_section->Name, code_section->SizeOfRawData);
	
	uint rlshellcodesz = (10 * pe.sections.size()) + 100;

	char *shellcode = (char *)malloc(rlshellcodesz);
	memcpy(shellcode, "\x68\xef\xbe\xed\x0d\x60\x6a\xff", 8);
	uint *_b = (uint*)(shellcode + 1);
	*_b = image_base+entrypoint;
	uint offset = 8;
	for (uint i = 0; i < pe.sections.size(); i++)
	{
		auto header = pe.sections[i].header;
		if (!check(".idata") || !check(".tls") || !check(".bss") || !check(".reloc"))
			continue;
		writePush(shellcode, header.SizeOfRawData, offset);
		writePush(shellcode, image_base+header.VirtualAddress, offset+5);
		cout << "Encrypting section " << header.Name << endl;
		offset += 10;
		for (uint j = 0; j < header.SizeOfRawData; j++)
			pe.sections[i].data[j]++;
		makeRWX(pe.sections[i].header);
	}
	char ss[] = "\x58\x83\xF8\xFF\x74\x10\x5B\xB9\x00\x00\x00\x00\xFE\x0C\x08\x41\x39\xD9\x75\xF8\xEB\xEA\x61\xC3";
	//char ss[] = "\x58\x83\xF8\xFF\x74\x10\x5B\xB9\x00\x00\x00\x00\x90\x90\x90\x41\x39\xD9\x75\xF8\xEB\xEA\x61\xC3";
	memcpy(shellcode+offset, ss, sizeof ss);
	uint alshellcodesize = align(rlshellcodesz, 0x200);


	char *newSection = (char*)malloc(pe.sections[idx].header.SizeOfRawData+alshellcodesize);
	memset(newSection + last_section_header->SizeOfRawData, 0x90, alshellcodesize);
	memcpy(newSection, pe.sections[idx].data, last_section_header->SizeOfRawData);

	memcpy(newSection+last_section_header->SizeOfRawData, shellcode, rlshellcodesz);
	pe.sections[idx].data = newSection;
	last_section_header->Misc.VirtualSize += alshellcodesize;
	last_section_header->SizeOfRawData += alshellcodesize;
	pe.pe_headers.OptionalHeader.AddressOfEntryPoint = last_section_header->VirtualAddress+last_section_header->SizeOfRawData - alshellcodesize;
	pe.save_to_file(&f1);
	f1.close();
	system("pause");
}
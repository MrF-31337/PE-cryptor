#include <iostream>
#include <fstream>
#include "pefile.hpp"
using namespace std;
pefile::pefile (ifstream *f)
{
	//read file
	f->seekg(0, SEEK_END);
	size = f->tellg();
	data = (char *)malloc(size);
	f->seekg(0, SEEK_SET);
	f->read(data, size);

	//get headers
	pe_headers_offset = *((int *)(data + 0x3c));
	printf("pe_header_offset = %x\n", pe_headers_offset);
	pe_headers = *((IMAGE_NT_HEADERS*)(data + pe_headers_offset));
	printf("%x\n", pe_headers.FileHeader.Machine);
	if (pe_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		puts("Error, can only pack x86 executables");
		system("pause");
		exit(0);
	}

	//get_sections
	pe_number_of_sections = pe_headers.FileHeader.NumberOfSections;
	for (int i = 0; i < pe_number_of_sections; i++)
	{
		pe_section section;
		section.header = *((IMAGE_SECTION_HEADER *)(data + pe_headers_offset + sizeof IMAGE_NT_HEADERS + sizeof IMAGE_SECTION_HEADER * i));
		section.data = data+section.header.PointerToRawData;
		sections.push_back(section);
	}
	pe_section last_section = sections[sections.size() - 1];
	sections_end = last_section.header.PointerToRawData + last_section.header.SizeOfRawData;
}
void pefile::add_section(IMAGE_SECTION_HEADER header, char *sectionData)
{
	pe_section new_section;
	memcpy(&new_section.header, &header, sizeof IMAGE_SECTION_HEADER);
	new_section.data = sectionData;
	sections.push_back(new_section);
	pe_headers.FileHeader.NumberOfSections++;
}

void write_n_bytes(ofstream *f, char b, int n) 
{
	for (int i = 0; i < n; i++)
		f->put(b);
}

void pefile::save_to_file(ofstream *outfile)
{
	int first_section_offset = pe_headers_offset + sizeof pe_headers + sizeof IMAGE_SECTION_HEADER*sections.size();
	int alignment = pe_headers.OptionalHeader.FileAlignment;
	first_section_offset += alignment - (first_section_offset % alignment);
	outfile->write(data, pe_headers_offset);
	outfile->write((char *)&pe_headers, sizeof pe_headers);
	int t = first_section_offset - sections[0].header.PointerToRawData;
	for (int i = 0; i < sections.size(); i++)
	{
		//sections[i].header.PointerToRawData += t;
		outfile->write((char *)&sections[i].header, sizeof IMAGE_SECTION_HEADER);
	}
	int padd = alignment-(outfile->tellp() % alignment);
	write_n_bytes(outfile, 0,padd);
	for (int i = 0; i < sections.size(); i++)
	{
		if (sections[i].data != NULL)
			outfile->write(sections[i].data, sections[i].header.SizeOfRawData);
		else
			write_n_bytes(outfile, 0xcc, sections[i].header.SizeOfRawData);
	}
	outfile->write(data+sections_end, size-sections_end);
}
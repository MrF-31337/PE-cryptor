#include "PE.h"

PE::PE(const string &fname)
{
	ifstream f(fname, ios::binary);
	if (!f.is_open()) {
		throw exception("Can't open input file.");
	}
	f.seekg(0, SEEK_END);
	size = f.tellg();
	data = (char*)malloc(size);
	f.seekg(0, SEEK_SET);
	f.read(data, size);
	f.close();

	dos_header = (IMAGE_DOS_HEADER*)data;
	pe_header = at_offset(data, dos_header->e_lfanew, IMAGE_NT_HEADERS);
	file_header = &pe_header->FileHeader;
	optional_header = &pe_header->OptionalHeader;
	data_directory = (IMAGE_DATA_DIRECTORY*)&optional_header->DataDirectory;

	if (file_header->Machine != IMAGE_FILE_MACHINE_I386)
		throw exception("Can only process X86 PE files.");

	section_headers_offset = dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	IMAGE_SECTION_HEADER* section_headers = at_offset(data, section_headers_offset, IMAGE_SECTION_HEADER);

	for (int i = 0; i < file_header->NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER *section_header = &section_headers[i];
		shared_ptr section = make_shared<Section>(section_header, &data[section_header->PointerToRawData], false);
		for (int j = 0; j < 16; j++)
		{
			if (section_header->VirtualAddress == optional_header->DataDirectory[j].VirtualAddress)
			{
				section->contains_in_data_directory = true;
				break;
			}
		}
		sections.push_back(section);
	}
	sort_sections();
}

void PE::add_section(shared_ptr<Section> &section)
{
	sections.push_back(section);

	sort_sections();
	shift_sections_if_necesseary(0, section_headers_offset + sections.size() * sizeof(IMAGE_SECTION_HEADER));
}

void PE::resize_section(shared_ptr<Section> &section, uint new_size)
{
	new_size = align(new_size, optional_header->FileAlignment);
	if (section->header->SizeOfRawData == new_size)
		return;
	else if (section->header->SizeOfRawData < new_size)
	{
		char* oldData = section->data;
		section->data = (char*)malloc(new_size);
		memset(section->data, 0, new_size);
		memcpy(section->data, oldData, section->header->SizeOfRawData);

		if (section->allocated)
			free(oldData);

		section->header->SizeOfRawData = new_size;

		auto section_iterator = find_if(sections.begin(), sections.end(), 
		[&section] (shared_ptr<Section> &section1) {
			return section->header->VirtualAddress == section1->header->VirtualAddress;
		});
		uint index = section_iterator - sections.begin() + 1;
		if (index != sections.size())
			shift_sections_if_necesseary(index, section->header->PointerToRawData + new_size);
	}
	section->header->SizeOfRawData = new_size;

}

void PE::save(const string& fname)
{
	ofstream f(fname, ios::binary);
	if (!f.is_open()) {
		throw exception("Can't open output file for writing.\nMaybe output file is running or opened in another program for writing.");
	}
	vector<shared_ptr<Section>> sections_sorted_by_addr;
	for (auto section : sections)
		sections_sorted_by_addr.push_back(section);
	sort(sections_sorted_by_addr.begin(), sections_sorted_by_addr.end(), 
		[](shared_ptr<PE::Section> &s1, shared_ptr<PE::Section> &s2) {
			return s1->header->VirtualAddress < s2->header->VirtualAddress;
		}
	);
	shared_ptr last_section = sections_sorted_by_addr[sections_sorted_by_addr.size() - 1];
	uint size_of_image = last_section->header->VirtualAddress + last_section->header->Misc.VirtualSize;

	size_of_image = align(size_of_image, optional_header->SectionAlignment);
	optional_header->SizeOfImage = size_of_image;
	file_header->NumberOfSections = sections.size();

	f.write(data, section_headers_offset);
	for (auto &section : sections)
		f.write((char*)section->header, sizeof(IMAGE_SECTION_HEADER));
	
	sort_sections();
	for (auto &section : sections)
	{
		write_n_bytes(f, 0, section->header->PointerToRawData - f.tellp());
		f.write(section->data, section->header->SizeOfRawData);
	}

	write_n_bytes(f, 0, size_of_image - f.tellp());

	f.close();
}

void PE::shift_sections_if_necesseary(uint index, uint new_offset)
{
	if (new_offset > sections[index]->header->PointerToRawData)
	{
		new_offset = align(new_offset, optional_header->FileAlignment);
		for (auto section = sections.begin() + index; section != sections.end(); section++)
		{
			(*section)->header->PointerToRawData = new_offset;
			new_offset += (*section)->header->SizeOfRawData;
		}
	}
}

uint PE::align(uint n, uint alignment)
{
	return n + alignment - (n % alignment);
}

void PE::write_n_bytes(ofstream& f, char b, int n)
{
	for (int i = 0; i < n; i++)
		f.put(b);
}

void PE::sort_sections()
{
	sort(sections.begin(), sections.end(), 
		[] (shared_ptr<PE::Section> &s1, shared_ptr<PE::Section> &s2) {
			return s1->header->PointerToRawData < s2->header->PointerToRawData;
		}
	);
}

PE::Section::Section(IMAGE_SECTION_HEADER* header, char* data, bool allocated) 
	: header(header), data(data), allocated(allocated)
{
}

PE::Section::~Section() {
	/*if (allocated)
		free(data);*/
}

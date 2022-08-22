#pragma once
#include <fstream>
#include <windows.h>
#include <vector>
#include <algorithm>
#include <exception>

using namespace std;

#define uint unsigned int
#define at_offset(x, y, z) ((z*)((char*)x+y))

class PE
{
public:

	class Section
	{
		friend PE;
	public:
		IMAGE_SECTION_HEADER* header;
		char* data;
		bool contains_in_data_directory = false;
		Section(IMAGE_SECTION_HEADER* header, char* data, bool allocated=true);
		~Section();
	private:
		bool allocated;
	};

	PE(const string &fname);
	void add_section(shared_ptr<Section> &section);
	void resize_section(shared_ptr<Section> &section, uint new_size);
	void save(const string &fname);
	void shift_sections_if_necesseary(uint index, uint new_offset);

	IMAGE_DOS_HEADER *dos_header;
	IMAGE_NT_HEADERS *pe_header;
	IMAGE_FILE_HEADER *file_header;
	IMAGE_OPTIONAL_HEADER *optional_header;
	IMAGE_DATA_DIRECTORY *data_directory;
	vector<shared_ptr<Section>> sections;

	static uint align(uint n, uint alignment);
private:
	uint size = 0;
	char* data;
	uint section_headers_offset;
	void write_n_bytes(ofstream& f, char b, int n);
	void sort_sections();
};


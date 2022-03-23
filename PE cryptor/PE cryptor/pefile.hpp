#pragma once
#pragma once
#include <iostream>
#include <fstream>
#include <windows.h>
#include <vector>
using namespace std;

typedef struct
{
	IMAGE_SECTION_HEADER header;
	char *data;
} pe_section;

class pefile
{
public:
	vector<pe_section> sections;
	int pe_headers_offset;
	int pe_number_of_sections;
	IMAGE_NT_HEADERS pe_headers;
	int a;
	pefile(ifstream *f);
	int sections_end;
	void add_section(IMAGE_SECTION_HEADER header, char *sectionData);
	void save_to_file(ofstream *outfile);
private:
	int size;
	char *data;
};
#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <locale.h>
#include <concrt.h>
#include <agents.h>
#include <strsafe.h>
#include <stdarg.h>

// Link against Advapi32 for AdjustTokenPrivileges/CloseServiceHandle
#pragma comment(lib, "advapi32.lib")

// Dummy function to prevent optimization stripping
void ForceReference(void* ptr) {
	if (ptr == nullptr) printf("");
}

// This mimics the pattern from sub_4030f0
void enumerate_services_pattern() {
	// Open Service Control Manager
	SC_HANDLE hSCManager = OpenSCManagerW(
		nullptr,  // lpMachineName
		nullptr,  // lpDatabaseName
		SC_MANAGER_ENUMERATE_SERVICE  // dwDesiredAccess (5 = 0x5)
		);

	if (hSCManager == nullptr) {
		return;
	}

	// First call: Get required buffer size
	DWORD pcbBytesNeeded = 0;
	DWORD servicesReturned = 0;

	EnumServicesStatusExW(
		hSCManager,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		nullptr,              // lpServices (null to get size)
		0,                   // cbBufSize (0 to get size)
		&pcbBytesNeeded,     // pcbBytesNeeded (output: required size)
		&servicesReturned,
		nullptr,             // lpResumeHandle
		nullptr              // pszGroupName
		);

	// This matches: sub_404a30(&lpServices_1, pcbBytesNeeded)
	// The vector constructor allocates a buffer of pcbBytesNeeded bytes
	// Using uint8_t to match the byte buffer pattern
	std::vector<uint8_t> lpServices_1(pcbBytesNeeded);

	// Now call again with the allocated buffer
	EnumServicesStatusExW(
		hSCManager,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		reinterpret_cast<LPBYTE>(lpServices_1.data()),
		pcbBytesNeeded,
		&pcbBytesNeeded,
		&servicesReturned,
		nullptr,
		nullptr
		);

	CloseServiceHandle(hSCManager);
}

// Prevent optimizer from removing our code with wide strings
void __declspec(noinline) use_stringw(const std::wstring& s) {
	std::wcout << s.length() << std::endl;
}

// Prevent optimizer from removing our code with normal strings
void __declspec(noinline) use_string(const std::string& s) {
	std::cout << s << std::endl;
}

void my_printf_wrapper(wchar_t* buffer, size_t size, const wchar_t* format, ...) {
	va_list args;
	va_start(args, format);
	StringCbVPrintfW(buffer, size, format, args);  // Now va_list is correct
	va_end(args);
}

void use_strsafe() {
	wchar_t buffer[256];
	my_printf_wrapper(buffer, sizeof(buffer), L"Test %d", 42);
	std::wcout << buffer << std::endl;
}

// Force String operations to get std::string symbols
void string_ops() {
	//Regular string operations
	std::string dest = "Hello";
	std::string source = "World";

	dest.append(source, 0, 3);
	std::cout << "Result 1: " << dest << std::endl;

	std::string dest2 = "Test";
	std::string source2 = "ExampleString";
	dest2.append(source2, 2, 5);
	std::cout << "Result 2: " << dest2 << std::endl;

	std::string dest3 = "A";
	std::string source3 = "BC";
	dest3.append(source3, 0, 2);
	std::cout << "Result 3: " << dest3 << std::endl;

	std::string dest4 = "This is a longer string";
	std::string source4 = " that needs heap";
	dest4.append(source4, 0, source4.length());
	std::cout << "Result 4: " << dest4 << std::endl;

	std::string dest5 = "Start";
	std::string source5 = "End";
	dest5.append(source5, 0, 100);
	std::cout << "Result 5: " << dest5 << std::endl;

	std::string dest6 = "Prefix";
	std::string source6 = "MiddleSuffix";
	dest6.append(source6, 6, 6);
	std::cout << "Result 6: " << dest6 << std::endl;

	std::string dest7 = "NoChange";
	std::string source7 = "Ignore";
	dest7.append(source7, 0, 0);
	std::cout << "Result 7: " << dest7 << std::endl;

	std::wstring wstr;
	std::wstring other = L"Hello";
	wstr.assign(other, 0, 5);

	//Wide string operations
	// operator+=
	std::wstring str1 = L"Hello";
	str1 += L" World";
	use_stringw(str1);

	// append(const wchar_t*)
	std::wstring str2 = L"Hello";
	str2.append(L" World");
	use_stringw(str2);

	// append(const wchar_t*, size_t count)
	std::wstring str3 = L"Hello";
	str3.append(L" World!!!", 6);  // Append only " World"
	use_stringw(str3);

	// append(wstring)
	std::wstring str4 = L"Hello";
	std::wstring suffix = L" World";
	str4.append(suffix);
	use_stringw(str4);

	// operator+
	std::wstring str5 = L"Hello" + std::wstring(L" World");
	use_stringw(str5);

	// Copy constructor
	std::wstring original = L"Original";
	std::wstring copy1(original);
	use_stringw(copy1);

	// Assignment operator
	std::wstring copy2;
	copy2 = original;
	use_stringw(copy2);

	// assign(const wchar_t*)
	std::wstring copy3;
	copy3.assign(L"Assigned");
	use_stringw(copy3);

	// assign(const wchar_t*, size_t count)
	std::wstring copy4;
	copy4.assign(L"Hello World", 5);  // Only "Hello"
	use_stringw(copy4);

	// assign(wstring, pos, count) - substring
	std::wstring copy5;
	copy5.assign(original, 0, 4);  // "Orig"
	use_stringw(copy5);

	// explicit use of std::string::find
	std::string haystack = "Hello World";
	size_t pos = haystack.find("World");  // Uses this function internally

	// explicit use of std::string::find
	std::wstring haystackw = L"Hello World";
	size_t pos2 = haystackw.find(L"World");  // Uses this function internally

	// find(const char* s, size_t pos) - 2 param version
	std::string findStr1 = "Hello World Hello";
	size_t p1 = findStr1.find("Hello", 6);  // Find "Hello" starting at position 6
	std::cout << "Found at: " << p1 << std::endl;

	// find(const char* s, size_t pos, size_t count) - 3 param version (the one you found!)
	std::string findStr2 = "Hello World";
	size_t p2 = findStr2.find("World!!!", 0, 5);  // Find first 5 chars of "World!!!" starting at 0
	std::cout << "Found at: " << p2 << std::endl;

	// Multiple variations
	std::string findStr3 = "abcabcabc";
	size_t p3 = findStr3.find("abc", 1, 3);  // Find "abc" starting at position 1
	std::cout << "Found at: " << p3 << std::endl;

	// Not found case
	size_t p4 = findStr3.find("xyz", 0, 3);  // Returns npos
	std::cout << "Not found: " << (p4 == std::string::npos) << std::endl;

	// std::string + const char* -> calls operator+(const string&, const char*)
	std::string prefix = "Hello";
	std::string result1 = prefix + " World";
	use_string(result1);

	// Multiple concatenations (each + generates a call)
	std::string name = "Alice";
	std::string greeting = std::string("Welcome, ") + name.c_str() + "!";
	use_string(greeting);

	// Different variations to ensure it's included
	std::string path = std::string("C:\\Users\\") + "test" + "\\file.txt";
	use_string(path);

	// const char* + std::string -> operator+(const char*, const string&)
	// This is a DIFFERENT overload!
	std::string suffix2 = "World";
	std::string result2 = "Hello " + suffix2;
	use_string(result2);

	// string + string -> operator+(const string&, const string&)
	// Also a different overload
	std::string a = "Hello";
	std::string b = " World";
	std::string result3 = a + b;
	use_string(result3);

	// operator+=
	std::string str1s = "Hello";
	str1s += " World";
	use_stringw(str1);

	// move operations
	std::wstring am = L"Original string content here";
	std::wstring bm;
	bm = std::move(am);
	use_stringw(bm);

	std::string ams = "Original string content here";
	std::string bms;
	bms = std::move(ams);
	use_string(bms);

	// insert(size_t pos, const char* s)
	std::string ins1 = "HelloWorld";
	ins1.insert(5, " ");  // "Hello World"
	use_string(ins1);

	// insert(size_t pos, const char* s, size_t count)
	std::string ins2 = "HelloWorld";
	ins2.insert(5, "---XXX", 3);  // "Hello---World"
	use_string(ins2);

	// insert(size_t pos, const string& str)
	std::string ins3 = "HelloWorld";
	std::string toInsert = " Beautiful ";
	ins3.insert(5, toInsert);  // "Hello Beautiful World"
	use_string(ins3);

	// insert(size_t pos, const string& str, size_t subpos, size_t sublen)
	std::string ins4 = "ABCDEF";
	std::string sub = "123456";
	ins4.insert(3, sub, 1, 3);  // "ABC234DEF"
	use_string(ins4);

	// insert(size_t pos, size_t count, char c)
	std::string ins5 = "HelloWorld";
	ins5.insert(5, 3, '-');  // "Hello---World"
	use_string(ins5);

	// wstring insert
	std::wstring wins1 = L"HelloWorld";
	wins1.insert(5, L" ");
	use_stringw(wins1);

	std::wstring wins2 = L"HelloWorld";
	wins2.insert(5, L"---XXX", 3);
	use_stringw(wins2);

	// replace(size_t pos, size_t count, const char* s)
	std::string rep1 = "Hello World";
	rep1.replace(6, 5, "Universe");  // "Hello Universe"
	use_string(rep1);

	// replace(size_t pos, size_t count, const char* s, size_t count2) - THE ONE YOU FOUND
	std::string rep2 = "Hello World";
	rep2.replace(6, 5, "Universe!!!", 8);  // "Hello Universe" (only first 8 chars)
	use_string(rep2);

	// replace(size_t pos, size_t count, const string& str)
	std::string rep3 = "Hello World";
	std::string replacement = "Beautiful";
	rep3.replace(6, 5, replacement);  // "Hello Beautiful"
	use_string(rep3);

	// replace(size_t pos, size_t count, const string& str, size_t pos2, size_t count2)
	std::string rep4 = "Hello World";
	std::string repSrc = "XXXUniverseYYY";
	rep4.replace(6, 5, repSrc, 3, 8);  // "Hello Universe"
	use_string(rep4);

	// replace(size_t pos, size_t count, size_t count2, char c)
	std::string rep5 = "Hello World";
	rep5.replace(6, 5, 3, '*');  // "Hello ***"
	use_string(rep5);

	// Shrinking replacement (count2 < count)
	std::string rep6 = "Hello World";
	rep6.replace(0, 5, "Hi", 2);  // "Hi World"
	use_string(rep6);

	// Growing replacement (count2 > count)
	std::string rep7 = "Hi World";
	rep7.replace(0, 2, "Hello", 5);  // "Hello World"
	use_string(rep7);

	// wstring replace
	std::wstring wrep1 = L"Hello World";
	wrep1.replace(6, 5, L"Universe");
	use_stringw(wrep1);

	std::wstring wrep2 = L"Hello World";
	wrep2.replace(6, 5, L"Universe!!!", 8);
	use_stringw(wrep2);
}

void vector_string_ops() {
	std::vector<std::string> vec;

	// push_back (copy)
	std::string s1 = "Hello";
	vec.push_back(s1);

	// push_back (move) - generates the function you found!
	vec.push_back(std::string("World"));
	vec.push_back(std::move(s1));

	// emplace_back
	vec.emplace_back("Emplaced");
	vec.emplace_back(10, 'x');  // string of 10 'x' characters

	// reserve - generates sub_4054d0
	std::vector<std::string> vec2;
	vec2.reserve(100);

	// Multiple push_backs to trigger growth
	//for (int i = 0; i < 20; i++) {
	//	vec2.push_back("Item " + std::to_string(i));
	//}

	// Use the vectors to prevent optimization
	for (const auto& str : vec) {
		use_string(str);
	}
	for (const auto& str : vec2) {
		use_string(str);
	}
}

int main() {
	// Force CRT & Exception Handling Symbols
	try {
		std::string s = "Force STL Types";
		throw std::exception("forcing EH");
	}
	catch (const std::exception& e) {
		printf("%s\n", e.what());
	}

	// Force Locale symbols (_GetLocaleNameFromLangCountry)
	setlocale(LC_ALL, "en-US");

	// Force Windows API Symbols
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		// This generates the AdjustTokenPrivileges reference
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		CloseHandle(hToken);
	}

	// Force AreFileApisANSI
	AreFileApisANSI();

	// Force Concurrency Runtime Symbols
	Concurrency::agent* agents[1] = { nullptr };
	Concurrency::agent_status status = Concurrency::agent_created;
	// We don't actually need to run it, just reference the function signature
	if (false) {
		Concurrency::agent::wait_for_all(0, agents, &status, 0);
	}

	enumerate_services_pattern();

	string_ops();

	vector_string_ops();

	use_strsafe();

	return 0;
}
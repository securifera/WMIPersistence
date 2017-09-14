#include <Windows.h>
#include <Wbemidl.h>
#include <comutil.h>
#include <strsafe.h> //StringCchCopy, swprintf_s

#include "wmi_core.h"

#define CREDUI_MAX_USERNAME_LENGTH 128

/****************************************************************************
 * Helper functions
 */

HRESULT remove_instance(IWbemServices *pSvc, wchar_t *resource_name, wchar_t *field_name, wchar_t *value)
{
	HRESULT hres = S_OK;
	IWbemCallResult *result = NULL;
	IWbemClassObject *pClass = NULL;
	wchar_t resource[WBEM_MAX_PATH+1];

	if(!pSvc)
		return S_FALSE;

	swprintf_s(resource, (size_t)WBEM_MAX_PATH, L"%s.%s=\"%s\"", resource_name, field_name, value);

	hres = pSvc->DeleteInstance(_bstr_t(resource), 0, NULL, &result);
	if(FAILED(hres)) {
		printf("[-] couldnt get object 0x%x\n", hres);
		return hres;
	}

	return hres;
}

HRESULT put_instance(IWbemServices *pSvc, IWbemClassObject *instance)
{
	HRESULT hres = S_OK;
	IWbemCallResult *pResult = NULL;

	// Write the instance to WMI. 
    hres = pSvc->PutInstance(instance, 0, NULL, &pResult);
	if(FAILED(hres)) {
		printf("[-] failed to PutInstance 0x%x\n", hres);
	}

	return hres;
}

HRESULT create_instance(IWbemServices *pSvc, wchar_t *class_name, IWbemClassObject **instance)
{
	HRESULT hres = S_OK;
    IWbemClassObject *pClass = NULL;
    IWbemCallResult *pResult = NULL;

	//input validation
	if(!pSvc || !instance || !class_name)
		return S_FALSE;

	hres = pSvc->GetObjectW(_bstr_t(class_name), 0, NULL, &pClass, &pResult); //TODO result checking
	if(FAILED(hres)) {
		printf("[-] couldnt get object 0x%x\n", hres);
		return hres;
	}
	
	// Create a new instance.
    pClass->SpawnInstance(0, instance);
    pClass->Release();  // Don't need the class any more

	return hres;
}

/****************************************************************************
 * Initialization functions
 */

HRESULT basic_conn(IWbemLocator *pLoc, IWbemServices **pSvc, COAUTHIDENTITY *authIdent, wchar_t *target, wchar_t *nmspace, wchar_t *name, wchar_t *pwd)
{
	HRESULT hres;
	wchar_t resource[CREDUI_MAX_USERNAME_LENGTH+1];
	wchar_t *slash, *dot = L".";
	wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH+1];
    wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH+1];

	//input validation
	if(!pLoc || !authIdent)
		return S_FALSE;
	if(!nmspace)
		nmspace = L"root\\cimv2";

	if(target)
		swprintf_s(resource, (size_t)CREDUI_MAX_USERNAME_LENGTH, L"\\\\%s\\%s", target, nmspace);
	else
		swprintf_s(resource, (size_t)CREDUI_MAX_USERNAME_LENGTH, L"%s", nmspace);

	hres = pLoc->ConnectServer(
        _bstr_t(resource),
        _bstr_t(name),    // User name
        _bstr_t(pwd),     // User password
        NULL, // Locale             
        NULL, // Security flags
        NULL, // Authority        
        NULL, // Context object 
        pSvc); // IWbemServices proxy
    if (FAILED(hres)) {
        printf("[-] Could not connect to resource. Error code = 0x%x\n", hres);
		return hres;
    }

	wprintf(L"[+] Connected to namespace: \\\\%s\\%s\n", target, nmspace);

	if(name) {
		//authentication settings settings
		memset(authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent->PasswordLength = (ULONG)wcslen(pwd);
		authIdent->Password = (USHORT*)pwd;

		slash = wcschr(name, L'\\');
		if(slash == NULL) {
			printf("[+] No domain specified for user...using .\\%s\n", name);
			authIdent->User = (USHORT*)name;
			authIdent->UserLength = (ULONG)wcslen(name);
			authIdent->Domain = (USHORT*)dot;
			authIdent->DomainLength = (ULONG)wcslen(dot);
		}
		else { //seperate domain name and username
			StringCchCopyW(pszUserName, CREDUI_MAX_USERNAME_LENGTH+1, slash+1);
			authIdent->User = (USHORT*)pszUserName;
			authIdent->UserLength = (ULONG)wcslen(pszUserName);
		
			StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH+1, name, slash - name);
			authIdent->Domain = (USHORT*)pszDomain;
			authIdent->DomainLength = (ULONG)(slash - name);
		}
		authIdent->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

		hres = CoSetProxyBlanket(
		   *pSvc,                          // Indicates the proxy to set
		   RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
		   RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
		   COLE_DEFAULT_PRINCIPAL,         // Server principal name 
		   RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
		   RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
		   authIdent,                     // client identity
		   EOAC_NONE                       // proxy capabilities 
		);
	}
	else { //no COAUTH info needed when using current creds??? i guess
		hres = CoSetProxyBlanket(
			*pSvc,                       // Indicates the proxy to set
			RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
			RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
			NULL,                        // Server principal name 
			RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
			NULL,                        // client identity
			EOAC_NONE                    // proxy capabilities 
		);
	}

	if(FAILED(hres)) {
        printf("[-] Could not set proxy blanket. Error code = 0x%x\n", hres);
        return hres;
    }

	return hres;
}

HRESULT init_com(IWbemLocator **pLoc)
{
	HRESULT hres;

	hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if(FAILED(hres)) {
        printf("Failed to initialize COM library. Error code = 0x%x\n", hres);
        return hres;
    }

	hres =  CoInitializeSecurity(
        NULL, 
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
        );            
    if(FAILED(hres)) {
        printf("Failed to initialize security. Error code = 0x%x\n", hres);
		CoUninitialize();
        return hres;
    }

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)pLoc);
    if (FAILED(hres)) {
        printf("Failed to create IWbemLocator object. Err code = 0x%x\n", hres);
		CoUninitialize();
        return hres;
    }

	return hres;
}
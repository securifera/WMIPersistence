#include <Windows.h>
#include <Wbemidl.h>
#include <comutil.h>
#include <strsafe.h> //swprintf_s

int ls(IWbemServices *pSvc, COAUTHIDENTITY *userAcct, wchar_t *path)
{
	HRESULT hres = S_OK;

	IEnumWbemClassObject* pEnum = NULL;
	IWbemClassObject *pCurObj = NULL;
	ULONG uReturn = 0;
	VARIANT vt;

	wchar_t query1[WBEM_MAX_QUERY], query2[WBEM_MAX_QUERY];
	wchar_t drive[3], *rel_path = NULL;

	if(!pSvc || !path || wcslen(path) < 3) {
		printf("[-] bad input given to LS command\n");
		return -1;
	}

	memset(drive, 0, sizeof(drive));
	drive[0] = path[0];
	drive[1] = path[1];
	//drive[2] = path[2];

	rel_path = wcschr(path, L'\\');
	if(!rel_path) {
		rel_path = L"\\";
	}

	 //Win32_CodecFile
	swprintf_s(query1, (size_t)WBEM_MAX_QUERY, L"SELECT * FROM Win32_Directory WHERE Drive='%s' AND Path='%s'", drive, rel_path);
	swprintf_s(query2, (size_t)WBEM_MAX_QUERY, L"SELECT * FROM CIM_Datafile WHERE Drive='%s' AND Path='%s'", drive, rel_path);
	//swprintf_s(query1, (size_t)WBEM_MAX_QUERY, L"SELECT * FROM Win32_Directory");
	//swprintf_s(query2, (size_t)WBEM_MAX_QUERY, L"SELECT * FROM CIM_Datafile");
	//wprintf(L"%s\n", query1);

	hres = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query1), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnum);
	if(FAILED(hres)) {
		printf("[-] LS: Failed to get Win32_Directory list: 0x%x\n", hres);
		goto cleanup;
	}

	if(userAcct) {
		hres = CoSetProxyBlanket(
			pEnum,                    // Indicates the proxy to set
			RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
			COLE_DEFAULT_PRINCIPAL,         // Server principal name 
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
			userAcct,                       // client identity
			EOAC_NONE                       // proxy capabilities 
			);
		if(FAILED(hres)) {
			printf("[-] LS: Failed CoSetProxyBlanket: 0x%x\n", hres);
			goto cleanup;
		}
	}

	while(pEnum) {
		hres = pEnum->Next(WBEM_INFINITE, 1, &pCurObj, &uReturn);
		if(uReturn == 0)
			break;

		hres = pCurObj->Get(L"Name", 0, &vt, 0, 0);
		printf("%S\n", vt.bstrVal);
		VariantClear(&vt);
		pCurObj->Release();
		pCurObj = NULL;
	}

	hres = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query2), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnum);
	if(FAILED(hres)) {
		printf("[-] LS: Failed to get Win32_Directory list: 0x%x\n", hres);
		goto cleanup;
	}

	if(userAcct) {
		hres = CoSetProxyBlanket(
			pEnum,                    // Indicates the proxy to set
			RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
			COLE_DEFAULT_PRINCIPAL,         // Server principal name 
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
			userAcct,                       // client identity
			EOAC_NONE                       // proxy capabilities 
			);
		if(FAILED(hres)) {
			printf("[-] LS: Failed CoSetProxyBlanket: 0x%x\n", hres);
			goto cleanup;
		}
	}

	while(pEnum) {
		hres = pEnum->Next(WBEM_INFINITE, 1, &pCurObj, &uReturn);
		if(uReturn == 0)
			break;

		hres = pCurObj->Get(L"Name", 0, &vt, 0, 0);
		printf("%S\n", vt.bstrVal);
		VariantClear(&vt);
		pCurObj->Release();
		pCurObj = NULL;
	}

cleanup:
	if(pCurObj)
		pCurObj->Release();
	if(pEnum)
		pEnum->Release();

	return 0;
}

int file_upload(IWbemServices *pSvc)
{
	//TODO
	return 0;
}
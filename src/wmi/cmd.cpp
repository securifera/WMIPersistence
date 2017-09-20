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

//helper functions
HRESULT method_object_helper(IWbemServices *pSvc, wchar_t *className, wchar_t *methodName, IWbemClassObject **pClassInstance)
{
	HRESULT hres = S_OK;
	IWbemClassObject *pClass = NULL;
	IWbemClassObject *pInParamsDefinition = NULL;

	//get class object
	hres = pSvc->GetObjectW(_bstr_t(className), 0, NULL, &pClass, NULL);
	if(FAILED(hres)) {
		wprintf(L"[-] Failed to get %S object: 0x%x\n", className, hres);
		return hres;
	}

	//get method object
	hres = pClass->GetMethod(_bstr_t(methodName), 0,  &pInParamsDefinition, NULL);
	if(FAILED(hres)) {
		wprintf(L"[-] Failed to get parameter defintions for %S method: 0x%x\n", methodName, hres);
		goto cleanup;
	}

	//spawn instance of method object
	hres = pInParamsDefinition->SpawnInstance(0, pClassInstance);
	if(FAILED(hres)) {
		printf("[-] Failed to spawn isntance of class: 0x%x\n", hres);
		goto cleanup;
	}

cleanup:
	if(pClass)
		pClass->Release();
	if(pInParamsDefinition)
		pInParamsDefinition->Release();

	return hres;
}

HRESULT registry_key_helper(IWbemServices *pSvc, wchar_t *name, wchar_t *method, HKEY hDefKey, wchar_t *sSubKeyName)
{
	HRESULT hres = S_OK;
	IWbemClassObject *pClassInstance = NULL;
	IWbemClassObject *pOutParams = NULL;
	VARIANT v;

	BSTR className = SysAllocString(name);
	BSTR methodName = SysAllocString(method);

	//get instance of method object
	hres = method_object_helper(pSvc, name, method, &pClassInstance);
	if(FAILED(hres)) {
		goto cleanup;
	}

	//set properties for method parameters
	VariantInit(&v);
	
	V_VT(&v) = VT_I4;
	V_I4(&v) = (UINT32)hDefKey;
	hres = pClassInstance->Put(_bstr_t(L"hDefKey"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set hDefKey property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(sSubKeyName);
	hres = pClassInstance->Put(_bstr_t(L"sSubKeyName"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set sSubKeyName property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	//execute method
	hres = pSvc->ExecMethod(className, methodName, 0, NULL, pClassInstance, &pOutParams, NULL);
	if(FAILED(hres)) {
		printf("[-] failed to execute method 0x%x\n", hres);
	}

	//TODO proper return value handling
    hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &v, NULL, 0);

cleanup:
	if(pClassInstance)
		pClassInstance->Release();
	if(pOutParams)
		pOutParams->Release();
	VariantClear(&v);
	SysFreeString(methodName);
	SysFreeString(className);

	return 0;
}

//registry functions
HRESULT create_key(IWbemServices *pSvc, HKEY hDefKey, wchar_t *sSubKeyName)
{
	HRESULT hres = S_OK;

	hres = registry_key_helper(pSvc, L"StdRegProv", L"CreateKey", hDefKey, sSubKeyName);

	return hres;
}

HRESULT delete_key(IWbemServices *pSvc, HKEY hDefKey, wchar_t *sSubKeyName)
{
	HRESULT hres = S_OK;

	hres = registry_key_helper(pSvc, L"StdRegProv", L"DeleteKey", hDefKey, sSubKeyName);

	return hres;
}

//other functions
HRESULT create_process(IWbemServices *pSvc, wchar_t *cmd)
{
	HRESULT hres = S_OK;
	IWbemClassObject *pClassInstance = NULL;
	IWbemClassObject *pOutParams = NULL;
	VARIANT v;

	//get instance of method object
	hres = method_object_helper(pSvc, L"Win32_Process", L"Create", &pClassInstance);
	if(FAILED(hres)) {
		goto cleanup;
	}

	//set properties for method parameters
	VariantInit(&v);

	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(cmd);
	hres = pClassInstance->Put(_bstr_t(L"CommandLine"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set CommandLine property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	//execute method
	hres = pSvc->ExecMethod(_bstr_t(L"Win32_Process"), _bstr_t(L"Create"), 0, NULL, pClassInstance, &pOutParams, NULL);
	if(FAILED(hres)) {
		printf("[-] failed to execute method 0x%x\n", hres);
	}

	//TODO proper return value handling
    hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &v, NULL, 0);

cleanup:
	if(pClassInstance)
		pClassInstance->Release();
	if(pOutParams)
		pOutParams->Release();
	VariantClear(&v);

	return hres;
}
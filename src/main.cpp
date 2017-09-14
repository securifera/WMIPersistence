#include <Windows.h>
#include <stdio.h>
#include <comutil.h> //_bstr_t

#include "config.h"
#include "wmi\wmi_core.h"
#include "wmi\wmi_persistence.h"
#include "wmi\cmd.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")

//test function for testing persistence related functions
HRESULT install_persistence(IWbemServices *pCimSvc, IWbemServices *pSubSvc)
{
	HRESULT hres = S_OK;
	IWbemClassObject *event_filter = NULL;
	IWbemClassObject *event_consumer = NULL;
	IWbemClassObject *binding = NULL;
	IWbemClassObject *timer = NULL;
	wchar_t *encCmd = L"ZQBjAGgAbwAgAHQAZQBzAHQA"; //echo test

	//input validation
	if(!pCimSvc || !pSubSvc)
		return S_FALSE;

	//create interval timer for root\cimv2
	//hres = create_instance(pCimSvc, L"__IntervalTimerInstruction", &timer);
	//hres = interval_timer(timer, DEFAULT_TIMERNAME, DEFAULT_NAMESPACE);

	//create eventfilter triggered on interval timer for root\subscription
	hres = create_instance(pSubSvc, L"__EventFilter", &event_filter);
	//hres = timing_trigger(event_filter, DEFAULT_EVENTFILTER_NAME, DEFAULT_NAMESPACE, DEFAULT_TIMERNAME);
	hres = process_start_trigger(event_filter, DEFAULT_EVENTFILTER_NAME, L"calc.exe", NULL);

	//create event consumer for root\subscription
	hres = create_instance(pSubSvc, L"ActiveScriptEventConsumer", &event_consumer);
	//hres = process_kill_action(event_consumer, DEFAULT_EVENTCONSUMER_NAME);
	hres = enc_powershell_action(event_consumer, DEFAULT_EVENTCONSUMER_NAME, encCmd);

	//create a binding for the eventfilter and eventconsumer for root\subscription
	hres = create_instance(pSubSvc, L"__FilterToConsumerBinding", &binding);
	hres = generic_binding(binding, L"ActiveScriptEventConsumer", DEFAULT_EVENTCONSUMER_NAME, DEFAULT_EVENTFILTER_NAME);

	//put all new instances in the wmi database
	//hres = put_instance(pCimSvc, timer);
	hres = put_instance(pSubSvc, event_filter);
	hres = put_instance(pSubSvc, event_consumer);
	hres = put_instance(pSubSvc, binding);

//cleanup:
	if(event_filter)
		event_filter->Release();
	if(event_consumer)
		event_consumer->Release();
	if(binding)
		binding->Release();

	return hres;
}

int test_cleanup(IWbemServices *pSubSvc)
{
	IWbemCallResult *result = NULL;

	remove_instance(pSubSvc, L"__EventFilter", L"Name", DEFAULT_EVENTFILTER_NAME);
	remove_instance(pSubSvc, L"ActiveScriptEventConsumer", L"Name", DEFAULT_EVENTCONSUMER_NAME);
	pSubSvc->DeleteInstance(_bstr_t(L"__FilterToConsumerBinding.Consumer=\"ActiveScriptEventConsumer.Name=\\\"DefaultEventConsumer\\\"\",Filter=\"__EventFilter.Name=\\\"DefaultEventFilter\\\"\""), 0, NULL, &result);

	return 0;
}

int test_init(IWbemLocator **pLoc, IWbemServices **pCimSvc, IWbemServices **pSubSvc, COAUTHIDENTITY *authIdent)
{
	HRESULT hres = S_OK;

	hres = init_com(pLoc);
	if(FAILED(hres)) {
		printf("[-] init_com failed\n");
		return -1;
	}

	hres = basic_conn(*pLoc, pSubSvc, authIdent, L"127.0.0.1", SUB_NAMESPACE, L".\\someuser", L"somepassword");
	if (FAILED(hres)) {
        printf("[-] Could not connect. Error code = 0x%x\n", hres);
		return -1;
    }

	hres = basic_conn(*pLoc, pCimSvc, authIdent, L"127.0.0.1", DEFAULT_NAMESPACE, L".\\someuser", L"somepassword");
	//hres = basic_conn(*pLoc, pCimSvc, authIdent, L"127.0.0.1", DEFAULT_NAMESPACE, NULL, NULL);
	if (FAILED(hres)) {
        printf("[-] Could not connect. Error code = 0x%x\n", hres);
		return -1;
    }

	return 0;
}

int main(int argc, char **argv)
{
	HRESULT hres = S_OK;
	IWbemLocator *pLoc = NULL;
	IWbemServices *pCimSvc = NULL;
	IWbemServices *pSubSvc = NULL;
	COAUTHIDENTITY authIdent;

	if(test_init(&pLoc, &pCimSvc, &pSubSvc, &authIdent) < 0)
		goto cleanup;

	hres = install_persistence(pCimSvc, pSubSvc);
	if(FAILED(hres)) {
		printf("[-] installing persistence failed %x\n", hres);
		goto cleanup;
	}

	test_cleanup(pSubSvc);

cleanup:
	if(pCimSvc)
		pCimSvc->Release();
	if(pSubSvc)
		pSubSvc->Release();
	if(pLoc)
		pLoc->Release();
	CoUninitialize();

	return 0;
}
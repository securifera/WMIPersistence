#ifndef WMI_CORE_H
#define WMI_CORE_H

#include <Windows.h>
#include <Wbemidl.h>

HRESULT remove_instance(IWbemServices *pSvc, wchar_t *resource_name, wchar_t *field_name, wchar_t *value);
HRESULT put_instance(IWbemServices *pSvc, IWbemClassObject *instance);
HRESULT create_instance(IWbemServices *pSvc, wchar_t *class_name, IWbemClassObject **instance);

HRESULT basic_conn(IWbemLocator *pLoc, IWbemServices **pSvc, COAUTHIDENTITY *authIdent, wchar_t *target, wchar_t *nmspace, wchar_t *name, wchar_t *pwd);
HRESULT init_com(IWbemLocator **pLoc);

#endif
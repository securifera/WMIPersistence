#ifndef CMD_H
#define CMD_H

#include <Wbemidl.h>

int ls(IWbemServices *pSvc, COAUTHIDENTITY *userAcct, wchar_t *path);
HRESULT create_key(IWbemServices *pSvc, HKEY hDefKey, wchar_t *sSubKeyName);
HRESULT delete_key(IWbemServices *pSvc, HKEY hDefKey, wchar_t *sSubKeyName);
HRESULT create_process(IWbemServices *pSvc, wchar_t *cmd);

#endif
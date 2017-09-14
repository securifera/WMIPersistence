#ifndef CMD_H
#define CMD_H

#include <Wbemidl.h>

int ls(IWbemServices *pSvc, COAUTHIDENTITY *userAcct, wchar_t *path);

#endif
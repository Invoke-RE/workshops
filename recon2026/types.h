/**
 * Windows Service Control Manager (SCM) Control Codes
 * 
 * These constants define the control codes that can be sent to a service's
 * HandlerFunction (registered via RegisterServiceCtrlHandler/Ex).
 * 
 * Reference: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/
 */

#ifndef SCM_CONTROL_CODES_H
#define SCM_CONTROL_CODES_H

/*============================================================================
 * SERVICE CONTROL CODES (sent to HandlerFunction)
 *============================================================================*/

typedef enum _SERVICE_CONTROL_CODE {
    SERVICE_CONTROL_STOP                    = 0x00000001,  // Requests the service to stop
    SERVICE_CONTROL_PAUSE                   = 0x00000002,  // Requests the service to pause
    SERVICE_CONTROL_CONTINUE                = 0x00000003,  // Requests the paused service to resume
    SERVICE_CONTROL_INTERROGATE             = 0x00000004,  // Requests the service to report its status
    SERVICE_CONTROL_SHUTDOWN                = 0x00000005,  // System is shutting down
    SERVICE_CONTROL_PARAMCHANGE             = 0x00000006,  // Service parameters have changed
    SERVICE_CONTROL_NETBINDADD              = 0x00000007,  // Network binding added
    SERVICE_CONTROL_NETBINDREMOVE           = 0x00000008,  // Network binding removed
    SERVICE_CONTROL_NETBINDENABLE           = 0x00000009,  // Network binding enabled
    SERVICE_CONTROL_NETBINDDISABLE          = 0x0000000A,  // Network binding disabled
    SERVICE_CONTROL_DEVICEEVENT             = 0x0000000B,  // Device event
    SERVICE_CONTROL_HARDWAREPROFILECHANGE   = 0x0000000C,  // Hardware profile changed
    SERVICE_CONTROL_POWEREVENT              = 0x0000000D,  // Power status changed
    SERVICE_CONTROL_SESSIONCHANGE           = 0x0000000E,  // Session changed
    SERVICE_CONTROL_PRESHUTDOWN             = 0x0000000F,  // System is about to shutdown
    SERVICE_CONTROL_TIMECHANGE              = 0x00000010,  // System time changed
    SERVICE_CONTROL_TRIGGEREVENT            = 0x00000020,  // Trigger event occurred
    /* User-defined control codes: 128-255 (0x80 - 0xFF) */
    SERVICE_CONTROL_USER_MIN                = 0x00000080,
    SERVICE_CONTROL_USER_MAX                = 0x000000FF
} SERVICE_CONTROL_CODE;


/*============================================================================
 * SERVICE STATES (dwCurrentState in SERVICE_STATUS)
 *============================================================================*/

typedef enum _SERVICE_STATE {
    SERVICE_STOPPED                         = 0x00000001,  // Service is not running
    SERVICE_START_PENDING                   = 0x00000002,  // Service is starting
    SERVICE_STOP_PENDING                    = 0x00000003,  // Service is stopping
    SERVICE_RUNNING                         = 0x00000004,  // Service is running
    SERVICE_CONTINUE_PENDING                = 0x00000005,  // Service continue is pending
    SERVICE_PAUSE_PENDING                   = 0x00000006,  // Service pause is pending
    SERVICE_PAUSED                          = 0x00000007   // Service is paused
} SERVICE_STATE;


/*============================================================================
 * SERVICE ACCEPTED CONTROLS (dwControlsAccepted in SERVICE_STATUS)
 * Note: These are flags, can be OR'd together
 *============================================================================*/

typedef enum _SERVICE_ACCEPT_FLAGS {
    SERVICE_ACCEPT_NONE                     = 0x00000000,  // No controls accepted
    SERVICE_ACCEPT_STOP                     = 0x00000001,  // Service can be stopped
    SERVICE_ACCEPT_PAUSE_CONTINUE           = 0x00000002,  // Service can be paused/continued
    SERVICE_ACCEPT_SHUTDOWN                 = 0x00000004,  // Service is notified on system shutdown
    SERVICE_ACCEPT_PARAMCHANGE              = 0x00000008,  // Service can receive parameter changes
    SERVICE_ACCEPT_NETBINDCHANGE            = 0x00000010,  // Service can receive network binding changes
    SERVICE_ACCEPT_HARDWAREPROFILECHANGE    = 0x00000020,  // Service can receive HW profile changes
    SERVICE_ACCEPT_POWEREVENT               = 0x00000040,  // Service can receive power events
    SERVICE_ACCEPT_SESSIONCHANGE            = 0x00000080,  // Service can receive session change events
    SERVICE_ACCEPT_PRESHUTDOWN              = 0x00000100,  // Service can receive preshutdown notification
    SERVICE_ACCEPT_TIMECHANGE               = 0x00000200,  // Service can receive time change events
    SERVICE_ACCEPT_TRIGGEREVENT             = 0x00000400   // Service can receive trigger events
} SERVICE_ACCEPT_FLAGS;


/*============================================================================
 * SERVICE TYPES (dwServiceType in SERVICE_STATUS)
 * Note: These are flags, can be OR'd together
 *============================================================================*/

typedef enum _SERVICE_TYPE_FLAGS {
    SERVICE_KERNEL_DRIVER                   = 0x00000001,  // Driver service
    SERVICE_FILE_SYSTEM_DRIVER              = 0x00000002,  // File system driver service
    SERVICE_ADAPTER                         = 0x00000004,  // Reserved
    SERVICE_RECOGNIZER_DRIVER               = 0x00000008,  // Reserved
    SERVICE_WIN32_OWN_PROCESS               = 0x00000010,  // Service runs in its own process
    SERVICE_WIN32_SHARE_PROCESS             = 0x00000020,  // Service shares a process
    SERVICE_USER_SERVICE                    = 0x00000040,  // User service (Windows 10+)
    SERVICE_USERSERVICE_INSTANCE            = 0x00000080,  // User service instance (Windows 10+)
    SERVICE_INTERACTIVE_PROCESS             = 0x00000100,  // Can interact with desktop (deprecated)
    SERVICE_PKG_SERVICE                     = 0x00000200   // Package service (Windows 10+)
} SERVICE_TYPE_FLAGS;


/*============================================================================
 * SERVICE ACCESS RIGHTS (for OpenService)
 * Note: These are flags, can be OR'd together
 *============================================================================*/

typedef enum _SERVICE_ACCESS_RIGHTS {
    SERVICE_QUERY_CONFIG                    = 0x00000001,  // Query service configuration
    SERVICE_CHANGE_CONFIG                   = 0x00000002,  // Change service configuration
    SERVICE_QUERY_STATUS                    = 0x00000004,  // Query service status
    SERVICE_ENUMERATE_DEPENDENTS            = 0x00000008,  // Enumerate dependents
    SERVICE_START                           = 0x00000010,  // Start the service
    SERVICE_STOP                            = 0x00000020,  // Stop the service
    SERVICE_PAUSE_CONTINUE                  = 0x00000040,  // Pause or continue the service
    SERVICE_INTERROGATE                     = 0x00000080,  // Interrogate the service
    SERVICE_USER_DEFINED_CONTROL            = 0x00000100,  // Send user-defined control codes
    SERVICE_DELETE                          = 0x00010000,  // DELETE access right
    SERVICE_READ_CONTROL                    = 0x00020000,  // READ_CONTROL access right
    SERVICE_WRITE_DAC                       = 0x00040000,  // WRITE_DAC access right
    SERVICE_WRITE_OWNER                     = 0x00080000,  // WRITE_OWNER access right
    SERVICE_ALL_ACCESS                      = 0x000F01FF   // All access rights
} SERVICE_ACCESS_RIGHTS;


/*============================================================================
 * SC_MANAGER ACCESS RIGHTS (for OpenSCManager)
 * Note: These are flags, can be OR'd together
 *============================================================================*/

typedef enum _SC_MANAGER_ACCESS_RIGHTS {
    SC_MANAGER_CONNECT                      = 0x00000001,  // Connect to SCM
    SC_MANAGER_CREATE_SERVICE               = 0x00000002,  // Create services
    SC_MANAGER_ENUMERATE_SERVICE            = 0x00000004,  // Enumerate services
    SC_MANAGER_LOCK                         = 0x00000008,  // Lock the database
    SC_MANAGER_QUERY_LOCK_STATUS            = 0x00000010,  // Query lock status
    SC_MANAGER_MODIFY_BOOT_CONFIG           = 0x00000020,  // Modify boot config
    SC_MANAGER_ALL_ACCESS                   = 0x000F003F   // All access rights
} SC_MANAGER_ACCESS_RIGHTS;

#endif /* SCM_CONTROL_CODES_H */


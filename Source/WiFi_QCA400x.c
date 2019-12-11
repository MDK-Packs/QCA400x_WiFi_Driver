/* -----------------------------------------------------------------------------
 * Copyright © 2019 Arm Limited (or its affiliates). All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * $Date:        11. December 2019
 * $Revision:    V1.2
 *
 * Driver:       Driver_WiFin (n = WIFI_QCA400x_DRV_NUM value)
 * Project:      WiFi Driver for 
 *               Qualcomm QCA400x based WiFi Module
 * --------------------------------------------------------------------------
 * Use the WiFi_QCA400x_Config.h file for compile time configuration 
 * of this driver.
 *
 * IMPORTANT NOTES:
 * Qualcomm QCA400x Host Driver SDK requires additional pin handling 
 * callback functions to be implemented (function template is available in 
 * QCA400x_HW.c file and should be adapted according to hardware).
 *
 * Known limitations:
 * - SocketRecv, SocketRecvFrom, SocketSend and SocketSendTo cannot detect 
 *   connection closure by peer as t_select function does not return that 
 *   status
 * - GetModuleInfo is not supported as QCOM API does not support retrieval 
 *   of this information
 * - SocketGetHostByName supports only IPv4 addresses as QCOM API 
 *   (qcom_dnsc_get_host_by_name, qcom_dnsc_get_host_by_name2) does 
 *   not support long host names and qcom_dns_resolver only supports IPv4
 * - Access Point mode is implemented but disabled in capabilities due to 
 *   inability to stop AP through QCOM API
 * -------------------------------------------------------------------------- */

/* History:
 *  Version 1.2
 *  - Socket functionality:
 *  -- Corrected Socket Accept
 *  Version 1.1
 *  - Removed send_timeout variable (socket send timeout can not be configured)
 *  - Reduced default socket receive timeout to 20s
 *  - Updated WiFi_GetNetInfo function to return WiFi security type (security type is save in WiFi_Activate)
 *  - Write to socket_arr[].handle variable is protected with a semaphore
 *  - Socket functions: Added additional safety checking of parameters and driver variables
 *  Version 1.0
 *    Initial version
 */


#include <stdint.h>
#include <string.h>

#include "a_config.h"
#include "atheros_wifi.h"
#include "atheros_stack_offload.h"
#include "qcom_api.h"

#include "cmsis_os2.h"
#include "cmsis_compiler.h"

#include "Driver_WiFi.h"

#include "WiFi_QCA400x_Config.h"        // Driver configuration settings


// WiFi Driver *****************************************************************

#define ARM_WIFI_DRV_VERSION ARM_DRIVER_VERSION_MAJOR_MINOR(1,2)        // Driver version

// Driver Version
static const ARM_DRIVER_VERSION driver_version = { ARM_WIFI_API_VERSION, ARM_WIFI_DRV_VERSION };

// Driver Capabilities
static const ARM_WIFI_CAPABILITIES driver_capabilities = { 
  1U,                                   // Station supported
  0U,                                   // Access Point not supported
  0U,                                   // Concurrent Station and Access Point not supported
  1U,                                   // WiFi Protected Setup (WPS) for Station supported
  0U,                                   // WiFi Protected Setup (WPS) for Access Point not supported
  0U,                                   // Access Point: event not generated on Station connect
  0U,                                   // Access Point: event not generated on Station disconnect
#if (WIFI_QCA400x_MODE_INT_STACK)       // If Internal Network Stack mode is compile-time selected
  0U,                                   // Event not generated on Ethernet frame reception in bypass mode
  0U,                                   // Bypass or pass-through mode (Ethernet interface) not supported
  1U,                                   // IP (UDP/TCP) (Socket interface) supported
  0U,                                   // IPv6 (Socket interface) not supported
#else                                   // If Bypass or Pass-through mode is compile-time selected
  1U,                                   // Event generated on Ethernet frame reception in bypass mode supported
  1U,                                   // Bypass or pass-through mode (Ethernet interface) supported
  0U,                                   // IP (UDP/TCP) (Socket interface) not supported
  0U,                                   // IPv6 (Socket interface) not supported
#endif
  1U,                                   // Ping (ICMP) supported
  0U                                    // Reserved (must be zero)
};

typedef struct {                        // Socket structure
  int32_t          handle;              // QCOM socket handle
  uint8_t          type;                // Type
  uint8_t          ip_len;              // 4 = IPv4, 16 = IPv6, other = invalid
  uint8_t          non_blocking;        // 0 = blocking, non-zero = non-blocking
  uint8_t          reserved;            // Reserved
  uint32_t         recv_timeout;        // Receive Timeout
  uint16_t         local_port;          // Local       port number
  uint16_t         remote_port;         // Remote host port number
  uint8_t          local_ip[16];        // Local host IP
  uint8_t          remote_ip[16];       // Remote host IP
} socket_t;

// Operating mode
#define OPER_MODE_STATION               (1U     )
#define OPER_MODE_AP                    (1U << 1)

// Global variables and structures
       QCA400x_WiFi                     wifiDev;

// Local variables and structures
static uint8_t                          driver_initialized = 0U;

static osEventFlagsId_t                 event_con_discon;

static uint8_t                          oper_mode;

static uint8_t                          scan_buf[WIFI_QCA400x_SCAN_BUF_LEN] __ALIGNED(4);

static uint32_t                         sta_lp_time;

#if (WIFI_QCA400x_MODE_INT_STACK)       // If Internal Network Stack mode is compile-time selected
static osSemaphoreId_t                  sockets_semaphore;
static uint8_t                          sta_dhcp_client;
static uint8_t                          ap_dhcp_server;
static uint32_t                         ap_dhcp_ip_begin;
static uint32_t                         ap_dhcp_ip_end;
static uint32_t                         ap_dhcp_lease_time;
static uint32_t                         ip_dns1;
static uint32_t                         ip_dns2;
static uint8_t                          ip6_dns1[16] __ALIGNED(4);
static uint8_t                          ip6_dns2[16] __ALIGNED(4);
static uint8_t                          security;

static socket_t                         socket_arr[MAX_SOCKETS_SUPPORTED];
#endif

#if (WIFI_QCA400x_MODE_PASSTHROUGH)     // If Bypass or Pass-through mode is compile-time selected
#define NUM_RX_FRAME  16                // must be 2^n; must be < 256
#define NUM_TX_FRAME  4

typedef struct {
  uint8_t         available;
  A_NATIVE_NETBUF pcb;
} tx_frame_t;

static ARM_WIFI_SignalEvent_t           signal_event_fn;

static volatile uint8_t                 rx_q_head;
static volatile uint8_t                 rx_q_tail;

static A_NETBUF *                       rx_netbuf_queue[NUM_RX_FRAME];

static uint8_t                          tx_buf  [NUM_TX_FRAME][1576];
static tx_frame_t                       tx_frame[NUM_TX_FRAME];
static uint32_t                         tx_idx;
#endif

// Function prototypes
static int32_t WiFi_Uninitialize   (void);
#if (WIFI_QCA400x_MODE_INT_STACK)       // If Internal Network Stack mode is compile-time selected
static int32_t WiFi_SocketRecvFrom (int32_t socket,       void *buf, uint32_t len,       uint8_t *ip, uint32_t *ip_len, uint16_t *port);
static int32_t WiFi_SocketSendTo   (int32_t socket, const void *buf, uint32_t len, const uint8_t *ip, uint32_t  ip_len, uint16_t  port);
static int32_t WiFi_SocketClose    (int32_t socket);
#endif                                                                                            
#if (WIFI_QCA400x_MODE_PASSTHROUGH)     // If Bypass or Pass-through mode is compile-time selected
static void Free_TxBuf             (void * param);
static void WiFi_EthFrameReceived  (A_NETBUF *a_netbuf_ptr);
#endif


// Helper Functions

/**
  \fn            void ResetVariables (void)
  \brief         Function that resets to all local variables to default values.
*/
static void ResetVariables (void) {
#if (WIFI_QCA400x_MODE_PASSTHROUGH)     // If Bypass or Pass-through mode is compile-time selected
  uint32_t i;

  signal_event_fn       = NULL;
#endif

  memset((void *)&wifiDev, 0, sizeof(wifiDev));

  oper_mode             = 0U;

  memset((void *)scan_buf, 0, sizeof(scan_buf));

  sta_lp_time           = 0U;

#if (WIFI_QCA400x_MODE_INT_STACK)       // If Internal Network Stack mode is compile-time selected
  sta_dhcp_client       = 1U;
  ap_dhcp_server        = 0U;
  ap_dhcp_ip_begin      = 0U;
  ap_dhcp_ip_end        = 0U;
  ap_dhcp_lease_time    = 0U;
  ip_dns1               = 0U;
  ip_dns2               = 0U;
  memset((void *)ip6_dns1, 0, sizeof(ip6_dns1));
  memset((void *)ip6_dns2, 0, sizeof(ip6_dns2));

  security              = ARM_WIFI_SECURITY_UNKNOWN;

  memset((void *)socket_arr, 0, sizeof(socket_arr));
#endif
#if (WIFI_QCA400x_MODE_PASSTHROUGH)     // If Bypass or Pass-through mode is compile-time selected
  rx_q_head = 0U;
  rx_q_tail = 0U;
  tx_idx    = 0U;

  memset((void *)rx_netbuf_queue, 0, sizeof(rx_netbuf_queue));
  memset((void *)tx_buf,          0, sizeof(tx_buf));

  for (i = 0U; i < NUM_TX_FRAME; i++) {
    tx_frame[i].available            = 1U;
    tx_frame[i].pcb.FREE             = &Free_TxBuf;
    tx_frame[i].pcb.PRIVATE          = (void *)i;
    tx_frame[i].pcb.FRAG[0].FRAGMENT = tx_buf[i];
    tx_frame[i].pcb.FRAG[0].LENGTH   = 0U;
  }

  wifiDev.FrameReceived_cb = WiFi_EthFrameReceived;
#endif
}

/**
  \fn            void ConnectCallback (uint32_t value, uint8_t device_id, uint8_t *bssid, uint32_t bssConn)
  \brief         Callback that is called when station connects/disconnects or AP start.
  \param[in]     value     Station connect status or AP start status
                   - value = 0: station disconnected
                   - value = 1: station connected/AP running
  \param[in]     device_id Device ID
  \param[in]     bssid     Unused
  \param[in]     bssConn   Unused
*/
static void ConnectCallback (uint32_t value, uint8_t device_id, uint8_t *bssid, uint32_t bssConn) {
  (void)bssid;
  (void)bssConn;

  if (device_id == 0U) {
    if (value == 1U) {                  // Station connected to AP
      osEventFlagsSet(event_con_discon, 2U);
    }
    if (value == 0x10U) {               // Station got IP from DHCP server
      osEventFlagsSet(event_con_discon, 4U);
    }
    if (value == 0U) {                  // Station disconnected from AP
      osEventFlagsSet(event_con_discon, 1U);
    }
  }
}

#if (WIFI_QCA400x_MODE_PASSTHROUGH)     // If Bypass or Pass-through mode is compile-time selected
/**
  \fn            void WiFi_EthFrameReceived (A_NETBUF* a_netbuf_ptr)
  \brief         Callback that is called when frame is received in bypass mode.
  \param[in]     a_netbuf_ptr   Pointer to structure describing received frame
*/
static void WiFi_EthFrameReceived (A_NETBUF *a_netbuf_ptr) {

  if (oper_mode != OPER_MODE_STATION) {
    A_NETBUF_FREE(a_netbuf_ptr);
    return;
  }

  if ((uint8_t)(rx_q_head - rx_q_tail) >= NUM_RX_FRAME) {
    // Rx Frame Queue is full. Dump the Frame.
    A_NETBUF_FREE(a_netbuf_ptr);
  } else {
    // Add to Queue
    rx_netbuf_queue[rx_q_head & (NUM_RX_FRAME - 1)] = a_netbuf_ptr;
    rx_q_head++;

    if (signal_event_fn != NULL) {
      signal_event_fn (ARM_WIFI_EVENT_ETH_RX_FRAME, NULL);
    }
  }
}

/**
  \fn            void Free_TxBuf (void * param)
  \brief         Free Transmit buffer
*/
static void Free_TxBuf (void * param) {
  uint32_t idx = (uint32_t)(((A_NATIVE_NETBUF *) param)->PRIVATE);
  tx_frame[idx].available = 1;
}
#endif


// Driver Functions

/**
  \fn            ARM_DRIVER_VERSION WiFi_GetVersion (void)
  \brief         Get driver version.
  \return        ARM_DRIVER_VERSION
*/
static ARM_DRIVER_VERSION WiFi_GetVersion (void) { return driver_version; }

/**
  \fn            ARM_WIFI_CAPABILITIES WiFi_GetCapabilities (void)
  \brief         Get driver capabilities.
  \return        ARM_WIFI_CAPABILITIES
*/
static ARM_WIFI_CAPABILITIES WiFi_GetCapabilities (void) { return driver_capabilities; }

/**
  \fn            int32_t WiFi_Initialize (ARM_WIFI_SignalEvent_t cb_event)
  \brief         Initialize WiFi Module.
  \param[in]     cb_event Pointer to ARM_WIFI_SignalEvent_t
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
*/
static int32_t WiFi_Initialize (ARM_WIFI_SignalEvent_t cb_event) {
  int32_t ret;

  if (driver_initialized != 0U) {       // If driver is already initialized
    return ARM_DRIVER_OK;
  }

#if (WIFI_QCA400x_MODE_PASSTHROUGH)     // If Bypass or Pass-through mode is compile-time selected
  signal_event_fn = cb_event;           // Update pointer to callback function
#else
  sockets_semaphore = osSemaphoreNew(1U, 1U, NULL);
  if (sockets_semaphore == NULL) {
    return ARM_DRIVER_ERROR;
  }
#endif

  ResetVariables();

  ret = ARM_DRIVER_OK;

  event_con_discon = osEventFlagsNew(NULL);
  if (event_con_discon == NULL) {
    ret = ARM_DRIVER_ERROR;
  }

  if (ret == ARM_DRIVER_OK) {
    if (ATHEROS_WIFI_IF.INIT(&wifiDev) != A_OK) {
      ret = ARM_DRIVER_ERROR;
    }
  }

  if (ret == ARM_DRIVER_OK) {           // If initialization succeeded
    driver_initialized = 1U;
  } else {                              // Else if initialization failed -> cleanup
    WiFi_Uninitialize();
  }

  return ret;
}

/**
  \fn            int32_t WiFi_Uninitialize (void)
  \brief         De-initialize WiFi Module.
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
*/
static int32_t WiFi_Uninitialize (void) {
  int32_t ret;
#if (WIFI_QCA400x_MODE_INT_STACK)       // If Internal Network Stack mode is compile-time selected
  uint8_t i;
#endif

  if (driver_initialized == 0U) {       // If driver is already uninitialized
    return ARM_DRIVER_OK;
  }

  ret = ARM_DRIVER_OK;

#if (WIFI_QCA400x_MODE_INT_STACK)       // If Internal Network Stack mode is compile-time selected
  // Close all open sockets
  for (i = 0U; i < MAX_SOCKETS_SUPPORTED; i++) {
    if (socket_arr[i].handle != 0) {
      if (WiFi_SocketClose(socket_arr[i].handle) != 0) {
        ret = ARM_DRIVER_ERROR;
        break;
      }
    }
  }

  osSemaphoreDelete(sockets_semaphore);
#endif

  if (ret == ARM_DRIVER_OK) {
    if (ATHEROS_WIFI_IF.STOP(&wifiDev) != A_OK) {
      ret = ARM_DRIVER_ERROR;
    }
  }

  if (ret == ARM_DRIVER_OK) {
    if (event_con_discon != NULL) {
      if (osEventFlagsDelete(event_con_discon) == osOK) {
        event_con_discon = NULL;
      } else {
        ret = ARM_DRIVER_ERROR;
      }
    }
  }

  if (ret == ARM_DRIVER_OK) {           // If uninitialization succeeded
#if (WIFI_QCA400x_MODE_PASSTHROUGH)     // If Bypass or Pass-through mode is compile-time selected
    signal_event_fn = NULL;             // Clear pointer to callback function
#endif
    ResetVariables();
    driver_initialized = 0U;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_PowerControl (ARM_POWER_STATE state)
  \brief         Control WiFi Module Power.
  \param[in]     state     Power state
                   - ARM_POWER_OFF                : Power off: no operation possible
                   - ARM_POWER_LOW                : Low-power mode: sleep or deep-sleep depending on ARM_WIFI_LP_TIMER option set
                   - ARM_POWER_FULL               : Power on: full operation at maximum performance
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (invalid state)
*/
static int32_t WiFi_PowerControl (ARM_POWER_STATE state) {
  int32_t ret;

  if (driver_initialized == 0U) {
    return ARM_DRIVER_ERROR;
  }

  ret = ARM_DRIVER_OK;

  switch (state) {
    case ARM_POWER_OFF:
      // Module does not support power-off
      ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      break;

    case ARM_POWER_LOW:
      if (sta_lp_time != 0U) {
        // If deep-sleep time was set for Station
        // If deep-sleep mode is activated the module will wake-up after specified time, 
        // for each new deep-sleep interval this function with parameter state = ARM_POWER_LOW 
        // has to be called again
        if ((qcom_suspend_enable(1)          != A_OK) || 
            (qcom_suspend_start(sta_lp_time) != A_OK)) {
          ret = ARM_DRIVER_ERROR;
        }
      }
      if (ret == ARM_DRIVER_OK) {
        if (qcom_power_set_mode(0U, REC_POWER, USER) != A_OK) {
          ret = ARM_DRIVER_ERROR;
        }
      }
      break;

    case ARM_POWER_FULL:
      if (qcom_suspend_enable(0) != A_OK) {
        ret = ARM_DRIVER_ERROR;
      }
      if (ret == ARM_DRIVER_OK) {
        if (qcom_power_set_mode(0U, MAX_PERF_POWER, USER) != A_OK) {
          ret = ARM_DRIVER_ERROR;
        }
      }
      break;

    default:
      ret = ARM_DRIVER_ERROR_PARAMETER;
      break;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_GetModuleInfo (char *module_info, uint32_t max_len)
  \brief         Get Module information.
  \param[out]    module_info Pointer to character buffer were info string will be returned
  \param[in]     max_len     Maximum length of string to return (including null terminator)
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (NULL module_info pointer or max_len equals to 0)
*/
static int32_t WiFi_GetModuleInfo (char *module_info, uint32_t max_len) {
  // QCOM API does not provide this information it could be implemented by editing 
  // Custom_Api_ReadyEvent function in the Qualcomm QCA400x Host Driver SDK
  return ARM_DRIVER_ERROR_UNSUPPORTED;
}

/**
  \fn            int32_t WiFi_SetOption (uint32_t interface, uint32_t option, const void *data, uint32_t len)
  \brief         Set WiFi Module Options.
  \param[in]     interface Interface (0 = Station, 1 = Access Point)
  \param[in]     option    Option to set
  \param[in]     data      Pointer to data relevant to selected option
  \param[in]     len       Length of data (in bytes)
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (invalid interface, NULL data pointer or len less than option specifies)
*/
static int32_t WiFi_SetOption (uint32_t interface, uint32_t option, const void *data, uint32_t len) {
  int32_t  ret;
  uint32_t u32;
#if (WIFI_QCA400x_MODE_INT_STACK)           // If Internal Network Stack mode is compile-time selected
  uint32_t mode, u32_arr[3];
#endif

  if ((interface > 1U) || (data == NULL) || (len < 4U)) {
    return ARM_DRIVER_ERROR_PARAMETER;
  }
  if (driver_initialized == 0U) {
    return ARM_DRIVER_ERROR;
  }

  ret = ARM_DRIVER_OK;

  switch (option) {
    case ARM_WIFI_TX_POWER:                 // Station/AP Set transmit power;                         data = &power,    len =  4, uint32_t: 0 .. 20 [dBm]
      u32 = *((uint32_t *)data);
      if ((u32 == 0U) || (u32 > 17U)) {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      if (ret == ARM_DRIVER_OK) {
        if (qcom_set_tx_power(0U, u32) != A_OK) {
          ret = ARM_DRIVER_ERROR;
        }
      }
      break;

    case ARM_WIFI_LP_TIMER:                 // Station    Set low-power deep-sleep time;              data = &time,     len =  4, uint32_t [seconds]: 0 = disable (default)
      if (interface == 0U) {
        sta_lp_time = *((uint32_t *)data);
      } else {
        // Not supported for AP interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_DTIM:                     // Station/AP Set DTIM interval;                          data = &dtim,     len =  4, uint32_t [beacons]
      if (interface == 0U) {
        u32 = *((uint32_t *)data);
        if (qcom_sta_set_listen_time(0U, u32) != A_OK) {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        // Not supported for AP interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_BEACON:                   //         AP Set beacon interval;                        data = &interval, len =  4, uint32_t [ms]
      if (interface == 1U) {
        u32 = *((uint32_t *)data);
        if (qcom_ap_set_beacon_interval(0U, u32) != A_OK) {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        // Not supported for Station interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

#if (WIFI_QCA400x_MODE_INT_STACK)           // If Internal Network Stack mode is compile-time selected
    case ARM_WIFI_IP:                       // Station/AP Set IPv4 static/assigned address;           data = &ip,       len =  4, uint8_t[4]
      if (interface == 0U) {
        if (qcom_ipconfig(0U, IPCFG_QUERY, &u32_arr[0], &u32_arr[1], &u32_arr[2]) == A_OK) {
          u32 = A_CPU2BE32(__UNALIGNED_UINT32_READ(data));
          if (qcom_ipconfig(0U, IPCFG_STATIC, &u32, &u32_arr[1], &u32_arr[2]) == A_OK) {
            sta_dhcp_client = 0U;
          } else {
            ret = ARM_DRIVER_ERROR;
          }
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        // Not supported for AP interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP_SUBNET_MASK:           // Station/AP Set IPv4 subnet mask;                       data = &mask,     len =  4, uint8_t[4]
      if (interface == 0U) {
        if (qcom_ipconfig(0U, IPCFG_QUERY, &u32_arr[0], &u32_arr[1], &u32_arr[2]) == A_OK) {
          u32  = A_CPU2BE32(__UNALIGNED_UINT32_READ(data));
          mode = IPCFG_STATIC;
          if (sta_dhcp_client != 0U) {
            mode = IPCFG_DHCP;
          }
          u32 = A_CPU2BE32(*((uint32_t *)data));
          if (qcom_ipconfig(0U, mode, &u32_arr[0], &u32, &u32_arr[2]) == A_OK) {
            sta_dhcp_client = 0U;
          } else {
            ret = ARM_DRIVER_ERROR;
          }
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        // Not supported for AP interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP_GATEWAY:               // Station/AP Set IPv4 gateway address;                   data = &ip,       len =  4, uint8_t[4]
      if (interface == 0U) {
        if (qcom_ipconfig(0U, IPCFG_QUERY, &u32_arr[0], &u32_arr[1], &u32_arr[2]) == A_OK) {
          u32 =  A_CPU2BE32(__UNALIGNED_UINT32_READ(data));
          mode = IPCFG_STATIC;
          if (sta_dhcp_client != 0U) {
            mode = IPCFG_DHCP;
          }
          u32 = A_CPU2BE32(*((uint32_t *)data));
          if (qcom_ipconfig(0U, mode, &u32_arr[0], &u32_arr[1], &u32) == A_OK) {
            sta_dhcp_client = 0U;
          } else {
            ret = ARM_DRIVER_ERROR;
          }
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        // Not supported for AP interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP_DNS1:                  // Station/AP Set IPv4 primary   DNS address;             data = &ip,       len =  4, uint8_t[4]
      if (interface == 0U) {
        qcom_dnsc_del_server_address((uint8_t *)&ip_dns1, ATH_AF_INET);   // Remove previous DNS1 address
        if ((qcom_dnsc_add_server_address((uint8_t *)data, ATH_AF_INET) == A_OK) && 
            (qcom_dnsc_enable(1) == A_OK)) {
          ip_dns1 = __UNALIGNED_UINT32_READ(data);
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        // Not supported for AP interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP_DNS2:                  // Station/AP Set IPv4 secondary DNS address;             data = &ip,       len =  4, uint8_t[4]
      if (interface == 0U) {
        qcom_dnsc_del_server_address((uint8_t *)&ip_dns2, ATH_AF_INET);   // Remove previous DNS1 address
        if ((qcom_dnsc_add_server_address((uint8_t *)data, ATH_AF_INET) == A_OK) && 
            (qcom_dnsc_enable(1) == A_OK)) {
          ip_dns2 = __UNALIGNED_UINT32_READ(data);
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        // Not supported for AP interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP_DHCP:                  // Station/AP Set IPv4 DHCP client/server enable/disable; data = &dhcp,     len =  4, uint32_t: 0 = disable, non-zero = enable (default)
      u32 = *((uint32_t *)data);
      if (interface == 0U) {
        if (u32 != 0U) {
          if (oper_mode == OPER_MODE_STATION) {
            // If Station is connected start DHCP client
            if (qcom_ipconfig(0U, IPCFG_QUERY, &u32_arr[0], &u32_arr[1], &u32_arr[2]) == A_OK) {
              if (qcom_ipconfig(0U, IPCFG_DHCP, &u32_arr[0], &u32_arr[1], &u32_arr[2]) == A_OK) {
                sta_dhcp_client = 1U;
              }
            } else {
              ret = ARM_DRIVER_ERROR;
            }
          } else {
            sta_dhcp_client = 1U;
          }
        } else {
          sta_dhcp_client = 0U;
        }
      } else {  // For AP interface
        if (u32 != 0U) {
          if (qcom_dhcps_set_pool(0U, ap_dhcp_ip_begin, ap_dhcp_ip_end, ap_dhcp_lease_time) == A_OK) {
            ap_dhcp_server = 1U;
          } else {
            ret = ARM_DRIVER_ERROR;
          }
        } else {
          if (qcom_dhcps_release_pool(0U) == A_OK) {
            ap_dhcp_server = 0U;
          } else {
            ret = ARM_DRIVER_ERROR;
          }
        }
      }
      break;

    case ARM_WIFI_IP_DHCP_POOL_BEGIN:       //         AP Set IPv4 DHCP pool begin address;           data = &ip,       len =  4, uint8_t[4]
      if (interface == 1U) {
        u32 = A_CPU2BE32(__UNALIGNED_UINT32_READ(data));
        if (qcom_dhcps_set_pool(0U, u32, ap_dhcp_ip_end, ap_dhcp_lease_time) == A_OK) {
          ap_dhcp_ip_begin = u32;
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        // Not supported for Station interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP_DHCP_POOL_END:         //         AP Set IPv4 DHCP pool end address;             data = &ip,       len =  4, uint8_t[4]
      if (interface == 1U) {
        u32 = A_CPU2BE32(__UNALIGNED_UINT32_READ(data));
        if (qcom_dhcps_set_pool(0U, ap_dhcp_ip_begin, u32, ap_dhcp_lease_time) == A_OK) {
          ap_dhcp_ip_end = u32;
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        // Not supported for Station interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP_DHCP_LEASE_TIME:       //         AP Set IPv4 DHCP lease time;                   data = &time,     len =  4, uint32_t [seconds]
      if (interface == 1U) {
        u32 = A_CPU2BE32(__UNALIGNED_UINT32_READ(data));
        if (qcom_dhcps_set_pool(0U, ap_dhcp_ip_begin, ap_dhcp_ip_end, u32) == A_OK) {
          ap_dhcp_lease_time = u32;
        } else {
          ret = ARM_DRIVER_ERROR_PARAMETER;
        }
      } else {
        // Not supported for Station interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP6_DNS1:                 // Station/AP Set IPv6 primary   DNS address;             data = &ip6,      len = 16, uint8_t[16]
      if (len >= 16U) {
        qcom_dnsc_del_server_address((uint8_t *)&ip6_dns1, ATH_AF_INET6);       // Remove previous DNS1 address
        if ((qcom_dnsc_add_server_address((uint8_t *)data, ATH_AF_INET6) == A_OK) && 
            (qcom_dnsc_enable(1) == A_OK)) {
          memcpy((void *)ip6_dns1, (void *)data, sizeof(ip6_dns1));
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      break;

    case ARM_WIFI_IP6_DNS2:                 // Station/AP Set IPv6 secondary DNS address;             data = &ip6,      len = 16, uint8_t[16]
      if (len >= 16U) {
        qcom_dnsc_del_server_address((uint8_t *)&ip6_dns2, ATH_AF_INET6);       // Remove previous DNS1 address
        if ((qcom_dnsc_add_server_address((uint8_t *)data, ATH_AF_INET6) == A_OK) && 
            (qcom_dnsc_enable(1) == A_OK)) {
          memcpy((void *)ip6_dns2, (void *)data, sizeof(ip6_dns2));
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      break;

    case ARM_WIFI_IP6_DHCP_MODE:            // Station/AP Set IPv6 DHCPv6 client mode;                data = &mode,     len =  4, uint32_t: ARM_WIFI_IP6_DHCP_xxx (default Off)
      u32 = *((uint32_t *)data);
      switch (u32) {
        case ARM_WIFI_IP6_DHCP_STATEFULL:
          // Only available and supported mode
          break;
        case ARM_WIFI_IP6_DHCP_OFF:
        case ARM_WIFI_IP6_DHCP_STATELESS:
        default:
          ret = ARM_DRIVER_ERROR_UNSUPPORTED;
          break;
      }
      break;
#endif

    default:
      ret = ARM_DRIVER_ERROR_UNSUPPORTED;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_GetOption (uint32_t interface, uint32_t option, void *data, uint32_t *len)
  \brief         Get WiFi Module Options.
  \param[in]     interface Interface (0 = Station, 1 = Access Point)
  \param[in]     option    Option to get
  \param[out]    data      Pointer to memory where data for selected option will be returned
  \param[in,out] len       Pointer to length of data (input/output)
                   - input: maximum length of data that can be returned (in bytes)
                   - output: length of returned data (in bytes)
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (invalid interface, NULL data or len pointer, or *len less than option specifies)
*/
static int32_t WiFi_GetOption (uint32_t interface, uint32_t option, void *data, uint32_t *len) {
  int32_t  ret;
#if (WIFI_QCA400x_MODE_INT_STACK)           // If Internal Network Stack mode is compile-time selected
  uint32_t u32;
  uint32_t dummy_u32;
  int32_t  dummy_i32;
  uint8_t  dummy_ip6[16];
#endif

  if ((interface > 1U) ||  (data == NULL) || (len == NULL) || (*len < 4U)) {
    return ARM_DRIVER_ERROR_PARAMETER;
  }
  if (driver_initialized == 0U) {
    return ARM_DRIVER_ERROR;
  }

  ret = ARM_DRIVER_OK;

  switch (option) {
    case ARM_WIFI_BSSID:                    // Station/AP Get BSSID of AP to connect or of AP;        data = &bssid,    len =  6, uint8_t[6]
      if (*len >= 6U) {
        if (qcom_get_bssid(0U, (uint8_t *)data) == A_OK) {
          *len = 6U;
        }
      } else {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      break;

    case ARM_WIFI_LP_TIMER:                 // Station    Get low-power deep-sleep time;              data = &time,     len =  4, uint32_t [seconds]: 0 = disable (default)
      if (interface == 0U) {
        *((uint32_t *)data) = sta_lp_time;
        *len = 4U;
      } else {
        // Not supported for AP interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_MAC:                      // Station/AP Get MAC;                                    data = &mac,      len =  6, uint8_t[6]
      if (*len >= 6U) {
        if (interface == 1U) {
          // For AP, MAC is same as BSSID
          if (qcom_get_bssid(0U, (uint8_t *)data) == A_OK) {
            *len = 6U;
          }
        } else {
          // For Station read MAC from wifiDev
          memcpy (data, wifiDev.ADDRESS, 6);
          *len = 6;
        }
      } else {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      break;

#if (WIFI_QCA400x_MODE_INT_STACK)           // If Internal Network Stack mode is compile-time selected
    case ARM_WIFI_IP:                       // Station/AP Get IPv4 static/assigned address;           data = &ip,       len =  4, uint8_t[4]
      if (qcom_ipconfig(0U, IPCFG_QUERY, &u32, &dummy_u32, &dummy_u32) == A_OK) {
        __UNALIGNED_UINT32_WRITE(data, A_CPU2BE32(u32));
        *len = 4U;
      } else {
        ret = ARM_DRIVER_ERROR;
      }
      break;

    case ARM_WIFI_IP_SUBNET_MASK:           // Station/AP Get IPv4 subnet mask;                       data = &mask,     len =  4, uint8_t[4]
      if (qcom_ipconfig(0U, IPCFG_QUERY, &dummy_u32, &u32, &dummy_u32) == A_OK) {
        __UNALIGNED_UINT32_WRITE(data, A_CPU2BE32(u32));
        *len = 4U;
      } else {
        ret = ARM_DRIVER_ERROR;
      }
      break;

    case ARM_WIFI_IP_GATEWAY:               // Station/AP Get IPv4 gateway address;                   data = &ip,       len =  4, uint8_t[4]
      if (qcom_ipconfig(0U, IPCFG_QUERY, &dummy_u32, &dummy_u32, &u32) == A_OK) {
        __UNALIGNED_UINT32_WRITE(data, A_CPU2BE32(u32));
        *len = 4U;
      } else {
        ret = ARM_DRIVER_ERROR;
      }
      break;

    case ARM_WIFI_IP_DNS1:                  // Station/AP Get IPv4 primary   DNS address;             data = &ip,       len =  4, uint8_t[4]
      __UNALIGNED_UINT32_WRITE(data, ip_dns1);
      *len = 4U;
      break;

    case ARM_WIFI_IP_DNS2:                  // Station/AP Get IPv4 secondary DNS address;             data = &ip,       len =  4, uint8_t[4]
      __UNALIGNED_UINT32_WRITE(data, ip_dns2);
      *len = 4U;
      break;

    case ARM_WIFI_IP_DHCP:                  // Station/AP Get IPv4 DHCP client/server enable/disable; data = &dhcp,     len =  4, uint32_t: 0 = disable, non-zero = enable (default)
      if (interface == 0U) {
        u32 = sta_dhcp_client;
      } else {  // For AP interface
        u32 = ap_dhcp_server;
      }
      *((uint32_t *)data) = u32;
      *len = 4U;
      break;

    case ARM_WIFI_IP_DHCP_POOL_BEGIN:       //         AP Get IPv4 DHCP pool begin address;           data = &ip,       len =  4, uint8_t[4]
      if (interface == 1U) {
        __UNALIGNED_UINT32_WRITE(data, A_CPU2BE32(ap_dhcp_ip_begin));
        *len = 4U;
      } else {
        // Not supported for Station interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP_DHCP_POOL_END:         //         AP Get IPv4 DHCP pool end address;             data = &ip,       len =  4, uint8_t[4]
      if (interface == 1U) {
        __UNALIGNED_UINT32_WRITE(data, A_CPU2BE32(ap_dhcp_ip_end));
        *len = 4U;
      } else {
        // Not supported for Station interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP_DHCP_LEASE_TIME:       //         AP Get IPv4 DHCP lease time;                   data = &time,     len =  4, uint32_t [seconds]
      if (interface == 1U) {
        __UNALIGNED_UINT32_WRITE(data, A_CPU2BE32(ap_dhcp_lease_time));
        *len = 4U;
      } else {
        // Not supported for Station interface
        ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      }
      break;

    case ARM_WIFI_IP6_GLOBAL:               // Station/AP Get IPv6 global address;                    data = &ip6,      len = 16, uint8_t[16]
      if (*len >= 16U) {
        if (qcom_ip6_address_get(0U, (uint8_t *)data, (uint8_t *)dummy_ip6, (uint8_t *)dummy_ip6, (uint8_t *)dummy_ip6, &dummy_i32, &dummy_i32, &dummy_i32, &dummy_i32) == A_OK) {
          *len = 16U;
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      break;

    case ARM_WIFI_IP6_LINK_LOCAL:           // Station/AP Get IPv6 link local address;                data = &ip6,      len = 16, uint8_t[16]
      if (*len >= 16U) {
        if (qcom_ip6_address_get(0U, (uint8_t *)dummy_ip6, (uint8_t *)data, (uint8_t *)dummy_ip6, (uint8_t *)dummy_ip6, &dummy_i32, &dummy_i32, &dummy_i32, &dummy_i32) == A_OK) {
          *len = 16U;
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      break;

    case ARM_WIFI_IP6_SUBNET_PREFIX_LEN:    // Station/AP Get IPv6 subnet prefix length;              data = &len,      len =  4, uint32_t: 1 .. 127
      if (qcom_ip6_address_get(0U, (uint8_t *)dummy_ip6, (uint8_t *)dummy_ip6, (uint8_t *)dummy_ip6, (uint8_t *)dummy_ip6, &dummy_i32, (int32_t *)data, &dummy_i32, &dummy_i32) == A_OK) {
        *len = 4U;
      } else {
        ret = ARM_DRIVER_ERROR;
      }
      break;

    case ARM_WIFI_IP6_GATEWAY:              // Station/AP Get IPv6 gateway address;                   data = &ip6,      len = 16, uint8_t[16]
      if (*len >= 16U) {
        if (qcom_ip6_address_get(0U, (uint8_t *)dummy_ip6, (uint8_t *)dummy_ip6, (uint8_t *)data, (uint8_t *)dummy_ip6, &dummy_i32, &dummy_i32, &dummy_i32, &dummy_i32) == A_OK) {
          *len = 16U;
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      } else {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      break;

    case ARM_WIFI_IP6_DNS1:                 // Station/AP Get IPv6 primary   DNS address;             data = &ip6,      len = 16, uint8_t[16]
      if (*len >= 16U) {
        memcpy((void *)data, (void *)ip6_dns1, 16);
        *len = 16U;
      } else {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      break;

    case ARM_WIFI_IP6_DNS2:                 // Station/AP Get IPv6 secondary DNS address;             data = &ip6,      len = 16, uint8_t[16]
      if (*len >= 16U) {
        memcpy((void *)data, (void *)ip6_dns2, 16);
        *len = 16U;
      } else {
        ret = ARM_DRIVER_ERROR_PARAMETER;
      }
      break;

    case ARM_WIFI_IP6_DHCP_MODE:            // Station/AP Get IPv6 DHCPv6 client mode;                data = &mode,     len =  4, uint32_t: ARM_WIFI_IP6_DHCP_xxx (default Off)
      *((uint32_t *)data) = ARM_WIFI_IP6_DHCP_STATEFULL;
      *len = 4U;
      break;

#endif
    default:
      ret = ARM_DRIVER_ERROR_UNSUPPORTED;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_Scan (ARM_WIFI_SCAN_INFO_t scan_info[], uint32_t max_num)
  \brief         Scan for available networks in range.
  \param[out]    scan_info Pointer to array of ARM_WIFI_SCAN_INFO_t structures where available Scan Information will be returned
  \param[in]     max_num   Maximum number of Network Information structures to return
  \return        number of ARM_WIFI_SCAN_INFO_t structures returned or error code
                   - value >= 0                   : Number of ARM_WIFI_SCAN_INFO_t structures returned
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (NULL scan_info pointer or max_num equal to 0)
*/
static int32_t WiFi_Scan (ARM_WIFI_SCAN_INFO_t scan_info[], uint32_t max_num) {
  int32_t                  ret;
  int16_t                  i, num;
  uint8_t                  security;
  qcom_start_scan_params_t params;
  ARM_WIFI_SCAN_INFO_t    *ptr_scan_info;
  QCOM_BSS_SCAN_INFO      *ptr_qcom_scan;

  if ((scan_info == NULL) || (max_num == 0U)) {
    return ARM_DRIVER_ERROR_PARAMETER;
  }
  if (driver_initialized == 0U) {
    return ARM_DRIVER_ERROR;
  }

  ret = ARM_DRIVER_OK;

  memset((void *)&params, 0, sizeof(qcom_start_scan_params_t));
  params.forceFgScan = 1U;
  if (qcom_set_ssid(0U, "") != A_OK) {
    ret = ARM_DRIVER_ERROR;
  }

  if (ret == ARM_DRIVER_OK) {
    if (qcom_set_scan(0U, &params) != A_OK) {
      ret = ARM_DRIVER_ERROR;
    }
  }

  if (ret == ARM_DRIVER_OK) {
    if (qcom_get_scan(0U, (QCOM_BSS_SCAN_INFO **)&ptr_qcom_scan, &num) != A_OK) {
      ret = ARM_DRIVER_ERROR;
    }
  }

  if (ret == ARM_DRIVER_OK) {
    if (num > (int32_t)max_num) {
      num = (int32_t)max_num;
    }

    ptr_scan_info = (ARM_WIFI_SCAN_INFO_t *)scan_info;

    for (i = 0; i < num; i++) {
      // Clear entry
      memset((void *)ptr_scan_info, 0, sizeof(ARM_WIFI_SCAN_INFO_t));

      // Extract SSID
      memcpy((void *)ptr_scan_info->ssid,  (void *)ptr_qcom_scan->ssid, ptr_qcom_scan->ssid_len);

      // Extract BSSID
      memcpy((void *)ptr_scan_info->bssid, (void *)ptr_qcom_scan->bssid, 6);

      // Extract security
      if (ptr_qcom_scan->security_enabled == 0) {
        security = ARM_WIFI_SECURITY_OPEN;
      } else {
        if ((ptr_qcom_scan->rsn_cipher == 0U) && (ptr_qcom_scan->wpa_cipher == 0U)) {
          security = ARM_WIFI_SECURITY_WEP;
        } else if (ptr_qcom_scan->rsn_cipher != 0U) {
          security = ARM_WIFI_SECURITY_WPA2;
        } else if (ptr_qcom_scan->wpa_cipher == 0U) {
          security = ARM_WIFI_SECURITY_WPA;
        } else {
          security = ARM_WIFI_SECURITY_UNKNOWN;
        }
      }
      ptr_scan_info->security = security;

      // Extract channel
      ptr_scan_info->ch = ptr_qcom_scan->channel;

      // Extract RSSI
      ptr_scan_info->rssi = ptr_qcom_scan->rssi;

      ptr_qcom_scan++;
      ptr_scan_info++;
    }
  }

  if (ret == ARM_DRIVER_OK) {
    ret = i;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_Activate (uint32_t interface, ARM_WIFI_CONFIG_t *config)
  \brief         Activate interface (Connect to a wireless network or activate an access point).
  \param[in]     interface Interface (0 = Station, 1 = Access Point)
  \param[in]     config    Pointer to ARM_WIFI_CONFIG_t structure where Configuration parameters are located
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_TIMEOUT     : Timeout occurred
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported (security type, channel autodetect or WPS not supported)
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (invalid interface, NULL config pointer or invalid configuration)
*/
static int32_t WiFi_Activate (uint32_t interface, const ARM_WIFI_CONFIG_t *config) {
  int32_t         ret;
  uint32_t        evt;
  WLAN_CRYPT_TYPE crypt_type;
  WLAN_AUTH_MODE  auth_mode;
#if (WIFI_QCA400x_MODE_INT_STACK)       // If Internal Network Stack mode is compile-time selected
  uint32_t        u32_arr[3];
#endif

  if ((interface > 1U) || (config == NULL)) {
    return ARM_DRIVER_ERROR_PARAMETER;
  }
  if (config == NULL) {
    return ARM_DRIVER_ERROR_PARAMETER;
  }
  if (driver_initialized == 0U) {
    return ARM_DRIVER_ERROR;
  }

  if (config->wps_method == ARM_WIFI_WPS_METHOD_NONE) {
    // For station connect if WPS is not used do a sanity check for ssid and security

    // SSID has to be a valid pointer
    if (config->ssid == NULL) {
      return ARM_DRIVER_ERROR_PARAMETER;
    }

    switch (config->security) {
      case ARM_WIFI_SECURITY_OPEN:
        break;
      case ARM_WIFI_SECURITY_WEP:
      case ARM_WIFI_SECURITY_WPA:
      case ARM_WIFI_SECURITY_WPA2:
        // Password has to be a valid pointer
        if (config->pass == NULL) {
          return ARM_DRIVER_ERROR_PARAMETER;
        }
        break;
      case ARM_WIFI_SECURITY_UNKNOWN:
      default:
        return ARM_DRIVER_ERROR_PARAMETER;
    }
  }

  // Valid channel settings are 0 for auto and 1 to 13 for exact channel selection
  if (config->ch > 13U) {
    return ARM_DRIVER_ERROR_PARAMETER;
  }

  switch (config->wps_method) {
    case ARM_WIFI_WPS_METHOD_NONE:
    case ARM_WIFI_WPS_METHOD_PBC:
      break;
    case ARM_WIFI_WPS_METHOD_PIN:
      // PIN has to be a valid pointer
      if (config->wps_pin == NULL) {
        return ARM_DRIVER_ERROR_PARAMETER;
      }
      break;
    default:
      return ARM_DRIVER_ERROR_PARAMETER;
  }

  // If Station is currently connected return error, user must call Deactivate first
  if ((interface == 0U) && (oper_mode == OPER_MODE_STATION)) {
    return ARM_DRIVER_ERROR;
  }

  // If AP is currently running return error, user must call Deactivate first
  if ((interface == 1U) && (oper_mode == OPER_MODE_AP)) {
    return ARM_DRIVER_ERROR;
  }

  ret = ARM_DRIVER_OK;

  if ((interface == 0U) && (config->wps_method != ARM_WIFI_WPS_METHOD_NONE)) {  // Station with WPS
    switch (config->wps_method) {
      case ARM_WIFI_WPS_METHOD_PBC:
        if (qcom_wps_start(0U, 1, 1, NULL) != A_OK) {
          ret = ARM_DRIVER_ERROR;
        }
        break;
      case ARM_WIFI_WPS_METHOD_PIN:
        if (qcom_wps_start(0U, 1, 0, (char *)config->wps_pin) != A_OK) {
          ret = ARM_DRIVER_ERROR;
        }
        break;
      default:
        ret = ARM_DRIVER_ERROR_PARAMETER;
        break;
    }
  } else {
    // Same procedure for Station and AP if WPS is not used for Station connection
    if (qcom_set_connect_callback(0U, &ConnectCallback) != A_OK) {
      ret = ARM_DRIVER_ERROR;
    }

    if (ret == ARM_DRIVER_OK) {
      if (qcom_op_set_mode(0U, ((interface == 0U) ? QCOM_WLAN_DEV_MODE_STATION : QCOM_WLAN_DEV_MODE_AP)) != A_OK) {
        ret = ARM_DRIVER_ERROR;
      }
    }

    if  (ret == ARM_DRIVER_OK) {
      if (qcom_set_ssid(0U, (char *)config->ssid) != A_OK) {
        ret = ARM_DRIVER_ERROR;
      }
    }

    if  (ret == ARM_DRIVER_OK) {
      switch (config->security) {
        case ARM_WIFI_SECURITY_OPEN:
          crypt_type = WLAN_CRYPT_NONE;
          auth_mode  = WLAN_AUTH_NONE;
          break;
        case ARM_WIFI_SECURITY_WEP:
          crypt_type = WLAN_CRYPT_WEP_CRYPT;
          auth_mode  = WLAN_AUTH_WEP;
          break;
        case ARM_WIFI_SECURITY_WPA:
          crypt_type = WLAN_CRYPT_AES_CRYPT;
          auth_mode  = WLAN_AUTH_WPA_PSK;
          break;
        case ARM_WIFI_SECURITY_WPA2:
          crypt_type = WLAN_CRYPT_AES_CRYPT;
          auth_mode  = WLAN_AUTH_WPA2_PSK;
          break;
        default:
          ret = ARM_DRIVER_ERROR_PARAMETER;
      }
    }

    if  (ret == ARM_DRIVER_OK) {
      if (qcom_sec_set_encrypt_mode(0U, crypt_type) != A_OK) {
        ret = ARM_DRIVER_ERROR;
      }
    }

    if  (ret == ARM_DRIVER_OK) {
      if (qcom_sec_set_auth_mode(0U, auth_mode) != A_OK) {
        ret = ARM_DRIVER_ERROR;
      }
    }

    if  (ret == ARM_DRIVER_OK) {
      if (qcom_sec_set_passphrase(0U, (char *)config->pass) != A_OK) {
        ret = ARM_DRIVER_ERROR;
      }
    }

    if  (ret == ARM_DRIVER_OK) {
      if (config->ch != 0U) {
        if (qcom_set_channel(0U, (uint16_t)config->ch) != A_OK) {
          ret = ARM_DRIVER_ERROR;
        }
      }
    }
  }

  if  (ret == ARM_DRIVER_OK) {
    osEventFlagsWait(event_con_discon, 7U, osFlagsWaitAny, 0U); // Read flags to clear them
    if (qcom_commit(0U) != A_OK) {
      ret = ARM_DRIVER_ERROR;
    }
  }

  if  (ret == ARM_DRIVER_OK) {
    // Wait for connect/ AP start event
    evt = osEventFlagsWait(event_con_discon, 2U, osFlagsWaitAny, WIFI_QCA400x_CON_DISCON_TIMEOUT);

    if (interface == 0U) {              // For Station interface
      if ((evt & 2U) != 0U) {           // If connect has succeeded
        oper_mode = OPER_MODE_STATION;
        security = config->security;
#if (WIFI_QCA400x_MODE_INT_STACK)       // If Internal Network Stack mode is compile-time selected
        if (sta_dhcp_client != 0U) {
          // Enable DHCP client, first read all settings then write same settings with DHCP enabled
          qcom_ipconfig(0U, IPCFG_QUERY, &u32_arr[0], &u32_arr[1], &u32_arr[2]);
          qcom_ipconfig(0U, IPCFG_DHCP,  &u32_arr[0], &u32_arr[1], &u32_arr[2]);

          // Wait for IP assigned event
          evt = osEventFlagsWait(event_con_discon, 4U, osFlagsWaitAny, WIFI_QCA400x_CON_DISCON_TIMEOUT);
          if ((evt & 0x80000000U) == 0U) {
            // If it was not an error or IP assigned set it back
            if ((evt & 4U) == 0U) {
              osEventFlagsSet(event_con_discon, evt);
            }
          } else {
            osDelay(250U);
          }
        }
#endif
      } else if (evt == osFlagsErrorTimeout) {
        ret = ARM_DRIVER_ERROR_TIMEOUT;
      } else {
        ret = ARM_DRIVER_ERROR;
      }
    } else {                            // For AP interface
      if ((evt & 2U) != 0U) {           // If AP has started
        oper_mode = OPER_MODE_AP;
      } else if (evt == osFlagsErrorTimeout) {
        ret = ARM_DRIVER_ERROR_TIMEOUT;
      } else {
        ret = ARM_DRIVER_ERROR;
      }
    }
  }

  return ret;
}

/**
  \fn            int32_t WiFi_Deactivate (uint32_t interface)
  \brief         Deactivate interface (Disconnect from a wireless network or deactivate an access point).
  \param[in]     interface Interface (0 = Station, 1 = Access Point)
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (invalid interface)
*/
static int32_t WiFi_Deactivate (uint32_t interface) {
  int32_t  ret;
  uint32_t evt;

  if (driver_initialized == 0U) {
    return ARM_DRIVER_ERROR;
  }

  ret = ARM_DRIVER_OK;

  if ((interface == 0U) && (oper_mode == OPER_MODE_STATION)) {
    if (qcom_set_connect_callback(0U, &ConnectCallback) != A_OK) {
      ret = ARM_DRIVER_ERROR;
    }

    if (ret == ARM_DRIVER_OK) {
      osEventFlagsWait(event_con_discon, 7U, osFlagsWaitAny, 0U); // Read flags to clear them
      if (qcom_disconnect(0U) == A_OK) {
        // Wait for disconnect event
        evt = osEventFlagsWait(event_con_discon, 1U, osFlagsWaitAny, WIFI_QCA400x_CON_DISCON_TIMEOUT);
        if ((evt & 1U) != 0U) {           // If disconnect has succeeded
          oper_mode = 0U;
          security = ARM_WIFI_SECURITY_UNKNOWN;
        } else if (evt == osFlagsErrorTimeout) {
          ret = ARM_DRIVER_ERROR_TIMEOUT;
        } else {
          ret = ARM_DRIVER_ERROR;
        }
      }
    }
  }
  if ((interface == 1U) && (oper_mode == OPER_MODE_AP)) {
    // AP cannot be stopped through QCOM API
    ret = ARM_DRIVER_ERROR;
  }

  return ret;
}

/**
  \fn            uint32_t WiFi_IsConnected (void)
  \brief         Get station connection status.
  \return        station connection status
                   - value != 0: Station connected
                   - value = 0: Station not connected
*/
static uint32_t WiFi_IsConnected (void) {

  if (oper_mode == OPER_MODE_STATION) {
    return 1U;
  }

  return 0U;
}

/**
  \fn            int32_t WiFi_GetNetInfo (ARM_WIFI_NET_INFO_t *net_info)
  \brief         Get station Network Information.
  \param[out]    net_info  Pointer to ARM_WIFI_NET_INFO_t structure where station Network Information will be returned
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed (station not connected)
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (invalid interface or NULL net_info pointer)
*/
static int32_t WiFi_GetNetInfo (ARM_WIFI_NET_INFO_t *net_info) {
  int32_t  ret;
  uint16_t u16;
  uint8_t  u8;

  if (net_info == NULL) {
    return ARM_DRIVER_ERROR_PARAMETER;
  }
  if (driver_initialized == 0U) {
    return ARM_DRIVER_ERROR;
  }

  ret = ARM_DRIVER_OK;

  // Get SSID
  if (qcom_get_ssid(0U, (char *)net_info->ssid) != A_OK) {
    ret = ARM_DRIVER_ERROR;
  }

  // Password cannot be retrieved with QCOM API
  // Load password with descriptive message string to inform the user 
  // that password is not available
  memcpy((void *)net_info->pass, "Not available!", 15);

  net_info->security = security;

  // Get channel
  if (qcom_get_channel(0U, &u16) == A_OK) {
    net_info->ch = (uint8_t)u16;
  } else {
    ret = ARM_DRIVER_ERROR;
  }

  // Get RSSI
  if (qcom_sta_get_rssi(0U, &u8) == A_OK) {
    net_info->rssi = (uint8_t)u8;
  } else {
    ret = ARM_DRIVER_ERROR;
  }

  return ret;
}

#if (WIFI_QCA400x_MODE_PASSTHROUGH)     // Pass-through mode  supported (internal network stack is bypassed)

/**
  \fn            int32_t WiFi_BypassControl (uint32_t interface, uint32_t mode)
  \brief         Enable or disable bypass (pass-through) mode. Transmit and receive Ethernet frames (IP layer bypassed and WiFi/Ethernet translation).
  \param[in]     interface Interface (0 = Station, 1 = Access Point)
  \param[in]     mode
                   - value = 1: all packets bypass internal IP stack
                   - value = 0: all packets processed by internal IP stack
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (invalid interface or mode)
*/
static int32_t WiFi_BypassControl (uint32_t interface, uint32_t mode) {
  if (mode != 0U) {
    return ARM_DRIVER_OK;
  } else {
    return ARM_DRIVER_ERROR;
  }
}

/**
  \fn            int32_t WiFi_EthSendFrame (uint32_t interface, const uint8_t *frame, uint32_t len)
  \brief         Send Ethernet frame (in bypass mode only).
  \param[in]     interface Interface (0 = Station, 1 = Access Point)
  \param[in]     frame    Pointer to frame buffer with data to send
  \param[in]     len      Frame buffer length in bytes
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_BUSY        : Driver is busy
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (invalid interface or NULL frame pointer)
*/
static int32_t WiFi_EthSendFrame (uint32_t interface, const uint8_t *frame, uint32_t len) {
  int32_t  ret;
  uint32_t idx;

  ret = 0;

  // Check parameters
  if ((frame == NULL) || (len == 0U) || (len > 1576U)) {
    ret = ARM_DRIVER_ERROR_PARAMETER;
  }
  if ((ret == 0) && (driver_initialized == 0U)) {
    ret = ARM_DRIVER_ERROR;
  }

  if (ret == 0) {
    ret = ARM_DRIVER_ERROR_BUSY;
    idx = tx_idx;
    if (tx_frame[idx].available == 0U) {
      ret = ARM_DRIVER_ERROR_BUSY;
    } else {
      tx_frame[idx].available = 0U;
      tx_frame[idx].pcb.FRAG[0].LENGTH = len;
      tx_frame[idx].pcb.FRAG[0].FRAGMENT = tx_buf[idx];
      memcpy(tx_buf[idx], frame, len);

      tx_idx++;
      if (tx_idx == NUM_TX_FRAME) {
        tx_idx = 0;
      }

      if (ATHEROS_WIFI_IF.SEND (&wifiDev, &tx_frame[idx].pcb, 0, 1, 0) == A_OK) {
        ret = ARM_DRIVER_OK;
      } else {
        tx_idx = idx;
        tx_frame[idx].available = 1U;
        ret = ARM_DRIVER_ERROR;
      }
    }
  }
  return ret;
}

/**
  \fn            int32_t WiFi_EthReadFrame (uint32_t interface, uint8_t *frame, uint32_t len)
  \brief         Read data of received Ethernet frame (in bypass mode only).
  \param[in]     interface Interface (0 = Station, 1 = Access Point)
  \param[in]     frame    Pointer to frame buffer for data to read into
  \param[in]     len      Frame buffer length in bytes
  \return        number of data bytes read or error code
                   - value >= 0                   : Number of data bytes read
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (invalid interface or NULL frame pointer)
*/
static int32_t WiFi_EthReadFrame (uint32_t interface, uint8_t *frame, uint32_t len) {
  int32_t ret;
  uint32_t sz;

  if ((frame == NULL) && (len != 0)) {
    ret = ARM_DRIVER_ERROR_PARAMETER;
  } else {
    ret = 0;
    if (rx_q_tail != rx_q_head) {
      // Queue is not empty
      if (frame != NULL) {
        sz = rx_netbuf_queue[rx_q_tail & (NUM_RX_FRAME - 1)]->native.FRAG[0].LENGTH;
        if (sz > len) {
          sz = len;
        }
        memcpy (frame, rx_netbuf_queue[rx_q_tail & (NUM_RX_FRAME - 1)]->native.FRAG[0].FRAGMENT, sz);
        ret = (int32_t)sz;
      }
      A_NETBUF_FREE(rx_netbuf_queue[rx_q_tail & (NUM_RX_FRAME - 1)]);
      rx_q_tail++;
    }
  }

  return ret;
}

/**
  \fn            uint32_t WiFi_EthGetRxFrameSize (uint32_t interface)
  \brief         Get size of received Ethernet frame (in bypass mode only).
  \param[in]     interface Interface (0 = Station, 1 = Access Point)
  \return        number of bytes in received frame
*/
static uint32_t WiFi_EthGetRxFrameSize (uint32_t interface) {
  uint32_t ret;

  ret = 0U;
  if (rx_q_tail != rx_q_head) {
    // Queue is not empty
    ret = rx_netbuf_queue[rx_q_tail & (NUM_RX_FRAME - 1)]->native.FRAG[0].LENGTH;
  }

  return ret;
}

#endif

#if (WIFI_QCA400x_MODE_INT_STACK)       // Enabled internal network stack (socket functions enabled)

/**
  \fn            int32_t WiFi_SocketCreate (int32_t af, int32_t type, int32_t protocol)
  \brief         Create a communication socket.
  \param[in]     af       Address family
  \param[in]     type     Socket type
  \param[in]     protocol Socket protocol
  \return        status information
                   - Socket identification number (>=0)
                   - ARM_SOCKET_EINVAL            : Invalid argument
                   - ARM_SOCKET_ENOTSUP           : Operation not supported
                   - ARM_SOCKET_ENOMEM            : Not enough memory
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketCreate (int32_t af, int32_t type, int32_t protocol) {
  int32_t ret = 0, i, handle, q_family, q_type;

  switch (af) {
    case ARM_SOCKET_AF_INET:
      q_family = ATH_AF_INET;
      break;
    case ARM_SOCKET_AF_INET6:
      q_family = ATH_AF_INET6;
      break;
    default:
      return ARM_SOCKET_EINVAL;
  }

  switch (type) {
    case ARM_SOCKET_SOCK_DGRAM:
      if (protocol != ARM_SOCKET_IPPROTO_UDP) {
        return ARM_SOCKET_EINVAL;
      }
      q_type = SOCK_DGRAM_TYPE;
      break;
    case ARM_SOCKET_SOCK_STREAM:
      if (protocol != ARM_SOCKET_IPPROTO_TCP) {
        return ARM_SOCKET_EINVAL;
      }
      q_type = SOCK_STREAM_TYPE;
      break;
    default:
      return ARM_SOCKET_EINVAL;
  }

  switch (protocol) {
    case ARM_SOCKET_IPPROTO_TCP:
      break;
    case ARM_SOCKET_IPPROTO_UDP:
      break;
    default:
      return ARM_SOCKET_EINVAL;
  }

  if (osSemaphoreAcquire(sockets_semaphore, 3000) != osOK) {
    return ARM_SOCKET_ERROR;
  }

  // Find free socket entry in socket_arr
  for (i = 0; i < MAX_SOCKETS_SUPPORTED; i++) {
    if (socket_arr[i].handle == 0) {
      break;
    }
  }
  if (i == MAX_SOCKETS_SUPPORTED) {
    ret = ARM_SOCKET_ENOMEM;            // No free socket is available
  }

  if (ret >= 0) {
    handle = qcom_socket(q_family, q_type, 0);
    if (handle != 0) {
      socket_arr[i].handle       = handle;
      socket_arr[i].type         = type;
      socket_arr[i].ip_len       = ((af == ARM_SOCKET_AF_INET6) ? 16U : 4U);
      socket_arr[i].non_blocking = 0U;
      socket_arr[i].recv_timeout = 20000U;
      socket_arr[i].local_port   = 0U;
      socket_arr[i].remote_port  = 0U;
      memset((void *)socket_arr[i].local_ip, 0, 16);
      memset((void *)socket_arr[i].remote_ip, 0, 16);
      ret = i;
    } else {
      ret = ARM_SOCKET_ERROR;
    }
  }

  osSemaphoreRelease (sockets_semaphore);

  return ret;
}

/**
  \fn            int32_t WiFi_SocketBind (int32_t socket, const uint8_t *ip, uint32_t ip_len, uint16_t port)
  \brief         Assign a local address to a socket.
  \param[in]     socket   Socket identification number
  \param[in]     ip       Pointer to local IP address
  \param[in]     ip_len   Length of 'ip' address in bytes
  \param[in]     port     Local port number
  \return        status information
                   - 0                            : Operation successful
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument (address or socket already bound)
                   - ARM_SOCKET_EADDRINUSE        : Address already in use
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketBind (int32_t socket, const uint8_t *ip, uint32_t ip_len, uint16_t port) {
  int32_t        i, ret, addr_len;
  union {
    SOCKADDR_T   addr;
    SOCKADDR_6_T addr6;
  } addr;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if ((ip == NULL) || (ip_len != socket_arr[socket].ip_len) || (port == 0U)) {
    return ARM_SOCKET_EINVAL;
  }
  if (socket_arr[socket].local_port != 0) {
    return ARM_SOCKET_EINVAL;
  }
  for (i = 0; i < MAX_SOCKETS_SUPPORTED; i++) {
    if (socket_arr[i].local_port == port) {
      return ARM_SOCKET_EADDRINUSE;
    }
  }
  if (socket_arr[socket].remote_port != 0) {
    return ARM_SOCKET_EISCONN;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  if (ip_len == 4U) {
    addr.addr.sin_port       = port;
    addr.addr.sin_family     = ATH_AF_INET;
    addr.addr.sin_addr       = A_CPU2BE32(__UNALIGNED_UINT32_READ(ip));
    addr_len                 = sizeof(SOCKADDR_T);
  } else {
    addr.addr6.sin6_family   = ATH_AF_INET6;
    addr.addr6.sin6_port     = port;
    addr.addr6.sin6_flowinfo = 0U;
    memcpy((void *)&(addr.addr6.sin6_addr), (void *)ip, ip_len);
    addr.addr6.sin6_scope_id = 0U;
    addr_len                 = sizeof(SOCKADDR_6_T);
  }

  ret = qcom_bind(socket_arr[socket].handle, (void *)&addr, addr_len);
  if (ret == 0) {
    // If socket bind succeeded
    socket_arr[socket].local_port = port;
    memcpy((void *)socket_arr[socket].local_ip, (void *)ip, ip_len);
  } else {
    ret = ARM_SOCKET_ERROR;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_SocketListen (int32_t socket, int32_t backlog)
  \brief         Listen for socket connections.
  \param[in]     socket   Socket identification number
  \param[in]     backlog  Number of connection requests that can be queued
  \return        status information
                   - 0                            : Operation successful
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument (socket not bound)
                   - ARM_SOCKET_ENOTSUP           : Operation not supported
                   - ARM_SOCKET_EISCONN           : Socket is already connected
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketListen (int32_t socket, int32_t backlog) {
  int32_t ret;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if (socket_arr[socket].type == ARM_SOCKET_SOCK_DGRAM) {
    return ARM_SOCKET_ENOTSUP;
  }
  if (socket_arr[socket].local_port == 0) {
    // Socket not bounded
    return ARM_SOCKET_EINVAL;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  ret = qcom_listen(socket_arr[socket].handle, backlog);
  if (ret < 0) {
    ret = ARM_SOCKET_ERROR;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_SocketAccept (int32_t socket, uint8_t *ip, uint32_t *ip_len, uint16_t *port)
  \brief         Accept a new connection on a socket.
  \param[in]     socket   Socket identification number
  \param[out]    ip       Pointer to buffer where address of connecting socket shall be returned (NULL for none)
  \param[in,out] ip_len   Pointer to length of 'ip' (or NULL if 'ip' is NULL)
                   - length of supplied 'ip' on input
                   - length of stored 'ip' on output
  \param[out]    port     Pointer to buffer where port of connecting socket shall be returned (NULL for none)
  \return        status information
                   - socket identification number of accepted socket (>=0)
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument (socket not in listen mode)
                   - ARM_SOCKET_ENOTSUP           : Operation not supported (socket type does not support accepting connections)
                   - ARM_SOCKET_ECONNRESET        : Connection reset by the peer
                   - ARM_SOCKET_ECONNABORTED      : Connection aborted locally
                   - ARM_SOCKET_EAGAIN            : Operation would block or timed out (may be called again)
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketAccept (int32_t socket, uint8_t *ip, uint32_t *ip_len, uint16_t *port) {
  int32_t        ret, i, handle, sockaddr_len;
  uint32_t       timeout, len;
  union {
    SOCKADDR_T   addr;
    SOCKADDR_6_T addr6;
  } addr;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if (socket_arr[socket].type == ARM_SOCKET_SOCK_DGRAM) {
    return ARM_SOCKET_ENOTSUP;
  }
  if (((ip != NULL) && (ip_len == NULL)) || ((ip_len != NULL) && (*ip_len < socket_arr[socket].ip_len))) {
    return ARM_SOCKET_EINVAL;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  if (osSemaphoreAcquire (sockets_semaphore, 1000)!= osOK) {
    return ARM_SOCKET_ERROR;
  }

  ret = 0;

  // Find free local socket entry in socket_arr
  for (i = 0; i < MAX_SOCKETS_SUPPORTED; i++) {
    if (socket_arr[i].handle == 0) {
      break;
    }
  }
  if (i == MAX_SOCKETS_SUPPORTED) {
    ret = ARM_SOCKET_ERROR;             // No free entry is available
  }

  if (ret >= 0) {
    if (socket_arr[i].non_blocking != 0U) {     // If non-blocking socket
      timeout = 0U;
    } else {                                    // Else if blocking socket
      timeout = 20000U;
    }

    if (t_select(Custom_Api_GetDriverCxt(0), (uint32_t)socket_arr[socket].handle, timeout) == 0) {
      handle = qcom_accept(socket_arr[socket].handle, (struct sockaddr *)(int32_t)&addr, &sockaddr_len);
      if (handle != 0) {
        if (sockaddr_len == sizeof(SOCKADDR_T)) {
          len = 4;
        } else {
          len = 16;
        }

        socket_arr[i].handle       = handle;
        socket_arr[i].type         = socket_arr[socket].type;
        socket_arr[i].ip_len       = socket_arr[socket].ip_len;
        socket_arr[i].non_blocking = socket_arr[socket].non_blocking;
        socket_arr[i].recv_timeout = socket_arr[socket].recv_timeout;
        socket_arr[i].local_port   = socket_arr[socket].local_port;
        socket_arr[i].remote_port  = addr.addr.sin_port;
        memcpy((void *)socket_arr[i].local_ip, (void *)socket_arr[socket].local_ip, socket_arr[socket].ip_len);
        if ((ip != NULL) && (ip_len != NULL) && (*ip_len >= len)) {
          memcpy((void *)socket_arr[i].remote_ip, (void *)&addr.addr.sin_addr, len);
          if (len == 4) {
            __UNALIGNED_UINT32_WRITE(ip, A_CPU2BE32(addr.addr.sin_addr));
          } else {
            memcpy((void *)ip, (void *)&addr.addr6.sin6_addr, 16);
          }
          *ip_len = len;
        }
        if (port != NULL) {
          *port = addr.addr.sin_port;
        }
        ret = i;
      } else {
        ret = ARM_SOCKET_ERROR;
      }
    }
  }

  osSemaphoreRelease (sockets_semaphore);

  return ret;
}

/**
  \fn            int32_t WiFi_SocketConnect (int32_t socket, const uint8_t *ip, uint32_t ip_len, uint16_t port)
  \brief         Connect a socket to a remote host.
  \param[in]     socket   Socket identification number
  \param[in]     ip       Pointer to remote IP address
  \param[in]     ip_len   Length of 'ip' address in bytes
  \param[in]     port     Remote port number
  \return        status information
                   - 0                            : Operation successful
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument
                   - ARM_SOCKET_EALREADY          : Connection already in progress
                   - ARM_SOCKET_EINPROGRESS       : Operation in progress
                   - ARM_SOCKET_EISCONN           : Socket is connected
                   - ARM_SOCKET_ECONNREFUSED      : Connection rejected by the peer
                   - ARM_SOCKET_ECONNABORTED      : Connection aborted locally
                   - ARM_SOCKET_EADDRINUSE        : Address already in use
                   - ARM_SOCKET_ETIMEDOUT         : Operation timed out
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketConnect (int32_t socket, const uint8_t *ip, uint32_t ip_len, uint16_t port) {
  int32_t        ret, addr_len;
  union {
    SOCKADDR_T   addr;
    SOCKADDR_6_T addr6;
  } addr;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if ((ip == NULL) || (ip_len != socket_arr[socket].ip_len) || (port == 0U)) {
    return ARM_SOCKET_EINVAL;
  }
  if (socket_arr[socket].type == ARM_SOCKET_SOCK_STREAM) {
    if ((ip[0] == 0) && (ip[1] == 0) && (ip[2] == 0) && (ip[3] == 0)) {
      return ARM_SOCKET_EINVAL;
    }
    if (socket_arr[socket].remote_port != 0U) {
      return ARM_SOCKET_EISCONN;
    }
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  ret = 0;

  if (ip_len == 4U) {
    addr.addr.sin_port       = port;
    addr.addr.sin_family     = ATH_AF_INET;
    addr.addr.sin_addr       = A_CPU2BE32(__UNALIGNED_UINT32_READ(ip));
    addr_len                 = sizeof(SOCKADDR_T);
  } else {
    addr.addr6.sin6_family   = ATH_AF_INET6;
    addr.addr6.sin6_port     = port;
    addr.addr6.sin6_flowinfo = 0U;
    memcpy((void *)&(addr.addr6.sin6_addr), (void *)ip, ip_len);
    addr.addr6.sin6_scope_id = 0U;
    addr_len                 = sizeof(SOCKADDR_6_T);
  }

  if (socket_arr[socket].type == ARM_SOCKET_SOCK_STREAM) {
    // Call qcom_connect only for stream (TCP) socket
    ret = qcom_connect(socket_arr[socket].handle, (struct sockaddr *)&addr, addr_len);
  }

  if (ret == 0) {

    // Store remote host IP and port for UDP (datagram)
    if (ip_len == 4U) {
      memcpy((void *)socket_arr[socket].remote_ip, (void *)&addr.addr.sin_addr,   ip_len);
    } else {
      memcpy((void *)socket_arr[socket].remote_ip, (void *)&addr.addr6.sin6_addr, ip_len);
    }
    socket_arr[socket].remote_port = port;
  } else {
    ret = ARM_SOCKET_ERROR;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_SocketRecv (int32_t socket, void *buf, uint32_t len)
  \brief         Receive data on a connected socket.
  \param[in]     socket   Socket identification number
  \param[out]    buf      Pointer to buffer where data should be stored
  \param[in]     len      Length of buffer (in bytes)
  \return        status information
                   - number of bytes received (>0)
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument (pointer to buffer or length)
                   - ARM_SOCKET_ENOTCONN          : Socket is not connected
                   - ARM_SOCKET_ECONNRESET        : Connection reset by the peer
                   - ARM_SOCKET_ECONNABORTED      : Connection aborted locally
                   - ARM_SOCKET_EAGAIN            : Operation would block or timed out (may be called again)
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketRecv (int32_t socket, void *buf, uint32_t len) {
  uint8_t  ip_udp[16];
  uint32_t ip_udp_len;
  uint16_t udp_port;

  if (socket_arr[socket].type == ARM_SOCKET_SOCK_DGRAM) {
    // For UDP reception SocketRecvFrom has to be used valid ip, ip_len and port pointers
    return (WiFi_SocketRecvFrom(socket, buf, len, ip_udp, &ip_udp_len, &udp_port));
  } else {
    return (WiFi_SocketRecvFrom(socket, buf, len, NULL, NULL, NULL));
  }
}

/**
  \fn            int32_t WiFi_SocketRecvFrom (int32_t socket, void *buf, uint32_t len, uint8_t *ip, uint32_t *ip_len, uint16_t *port)
  \brief         Receive data on a socket.
  \param[in]     socket   Socket identification number
  \param[out]    buf      Pointer to buffer where data should be stored
  \param[in]     len      Length of buffer (in bytes)
  \param[out]    ip       Pointer to buffer where remote source address shall be returned (NULL for none)
  \param[in,out] ip_len   Pointer to length of 'ip' (or NULL if 'ip' is NULL)
                   - length of supplied 'ip' on input
                   - length of stored 'ip' on output
  \param[out]    port     Pointer to buffer where remote source port shall be returned (NULL for none)
  \return        status information
                   - number of bytes received (>0)
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument (pointer to buffer or length)
                   - ARM_SOCKET_ENOTCONN          : Socket is not connected
                   - ARM_SOCKET_ECONNRESET        : Connection reset by the peer
                   - ARM_SOCKET_ECONNABORTED      : Connection aborted locally
                   - ARM_SOCKET_EAGAIN            : Operation would block or timed out (may be called again)
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketRecvFrom (int32_t socket, void *buf, uint32_t len, uint8_t *ip, uint32_t *ip_len, uint16_t *port) {
  int32_t        ret, from_addr_len, len_to_recv, len_recv;
  uint32_t       timeout;
  char          *rx_buf;
  union {
    SOCKADDR_T   addr;
    SOCKADDR_6_T addr6;
  } from_addr;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if ((buf == NULL) || (len == 0U)) {
    return ARM_SOCKET_EINVAL;
  }
  if (socket_arr[socket].type == ARM_SOCKET_SOCK_STREAM) {
    if (socket_arr[socket].remote_port == 0U) {
      return ARM_SOCKET_ENOTCONN;
    }
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  ret = 0;

  timeout = socket_arr[socket].recv_timeout;
  if (socket_arr[socket].non_blocking != 0U) {
    // Non-blocking is emulated with timout of 1 ms
    timeout = 1U;
  }

  len_to_recv = (int32_t)len;
  len_recv    = 0;
  do {
    if ((A_STATUS)t_select(Custom_Api_GetDriverCxt(0), socket_arr[socket].handle, timeout) == A_OK) {
      rx_buf = NULL;
      if (ip != NULL) {
        ret  = qcom_recvfrom(socket_arr[socket].handle, &rx_buf, len_to_recv - len_recv, 0, (struct sockaddr *)&from_addr, &from_addr_len);
      } else {
        ret  = qcom_recv    (socket_arr[socket].handle, &rx_buf, len_to_recv - len_recv, 0);
      }
      if (ret > 0) {
        memcpy((void *)((char *)buf + len_recv), (void *)rx_buf, ret);
        len_recv += ret;
        if (from_addr_len == sizeof(SOCKADDR_T)) {
          if (ip != NULL) {
            __UNALIGNED_UINT32_WRITE(ip, A_CPU2BE32(from_addr.addr.sin_addr));
          }
          if (ip_len != NULL) {
            *ip_len = 4U;
          }
          if (port != NULL) {
            *port = from_addr.addr.sin_port;
          }
        }
        if (from_addr_len == sizeof(SOCKADDR_6_T)) {
          if (ip != NULL) {
            memcpy((void *)ip, (void *)&from_addr.addr6.sin6_addr, 16);
          }
          if (ip_len != NULL) {
            *ip_len = 16U;
          }
          if (port != NULL) {
            *port = from_addr.addr6.sin6_port;
          }
        }
      } else {
        // If error
        ret = ARM_SOCKET_ERROR;
      }
      if(rx_buf != NULL) {
        zero_copy_free(rx_buf);
      }
      if (ret != 0) {
        break;
      }
    } else {
      // If timeout
      break;
    }
  } while (len_to_recv > len_recv);

  if (ret > 0) {
    ret = len_recv;
  } else if (ret == 0) {
    // If timed out in blocking mode or no data available in non-blocking mode
    ret = ARM_SOCKET_EAGAIN;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_SocketSend (int32_t socket, const void *buf, uint32_t len)
  \brief         Send data on a connected socket.
  \param[in]     socket   Socket identification number
  \param[in]     buf      Pointer to buffer containing data to send
  \param[in]     len      Length of data (in bytes)
  \return        status information
                   - number of bytes sent (>0)
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument (pointer to buffer or length)
                   - ARM_SOCKET_ENOTCONN          : Socket is not connected
                   - ARM_SOCKET_ECONNRESET        : Connection reset by the peer
                   - ARM_SOCKET_ECONNABORTED      : Connection aborted locally
                   - ARM_SOCKET_EAGAIN            : Operation would block or timed out (may be called again)
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketSend (int32_t socket, const void *buf, uint32_t len) {
  uint8_t   ip_udp[16];
  uint32_t  ip_udp_len, u32;
  uint16_t  udp_port;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if ((buf == NULL) || (len == 0U)) {
    return ARM_SOCKET_EINVAL;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  if (socket_arr[socket].type == ARM_SOCKET_SOCK_DGRAM) {
    // For UDP send SocketSendTo has to be used with ip, ip_len and port parameters 
    // that were provided on SocketConnect
    ip_udp_len = socket_arr[socket].ip_len;
    udp_port   = socket_arr[socket].remote_port;
    if (socket_arr[socket].ip_len == 4) {
      u32    = *((uint32_t *)socket_arr[socket].remote_ip);
      __UNALIGNED_UINT32_WRITE(ip_udp, A_CPU2BE32(u32));
    } else {
      memcpy((void *)ip_udp, (void *)socket_arr[socket].remote_ip, ip_udp_len);
    }

    return (WiFi_SocketSendTo(socket, buf, len, (const uint8_t *)ip_udp, ip_udp_len, udp_port));
  } else {
    return (WiFi_SocketSendTo(socket, buf, len, NULL, 0U, 0U));
  }
}

/**
  \fn            int32_t WiFi_SocketSendTo (int32_t socket, const void *buf, uint32_t len, const uint8_t *ip, uint32_t ip_len, uint16_t port)
  \brief         Send data on a socket.
  \param[in]     socket   Socket identification number
  \param[in]     buf      Pointer to buffer containing data to send
  \param[in]     len      Length of data (in bytes)
  \param[in]     ip       Pointer to remote destination IP address
  \param[in]     ip_len   Length of 'ip' address in bytes
  \param[in]     port     Remote destination port number
  \return        status information
                   - number of bytes sent (>0)
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument (pointer to buffer or length)
                   - ARM_SOCKET_ENOTCONN          : Socket is not connected
                   - ARM_SOCKET_ECONNRESET        : Connection reset by the peer
                   - ARM_SOCKET_ECONNABORTED      : Connection aborted locally
                   - ARM_SOCKET_EAGAIN            : Operation would block or timed out (may be called again)
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketSendTo (int32_t socket, const void *buf, uint32_t len, const uint8_t *ip, uint32_t ip_len, uint16_t port) {
  int32_t        ret, to_addr_len, len_sent, len_to_send, len_curr;
  char          *tx_buf;
  union {
    SOCKADDR_T   addr;
    SOCKADDR_6_T addr6;
  } to_addr;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if ((buf == NULL) || (len == 0U)) {
    return ARM_SOCKET_EINVAL;
  }
  if ((ip != NULL) && (ip_len != socket_arr[socket].ip_len)) {
    return ARM_SOCKET_EINVAL;
  }
  if (socket_arr[socket].type == ARM_SOCKET_SOCK_STREAM) {
    if (socket_arr[socket].remote_port == 0U) {
      return ARM_SOCKET_ENOTCONN;
    }
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  ret = 0;

  if (len > WIFI_QCA400x_MAX_PACKET_LEN) {
    tx_buf = custom_alloc (WIFI_QCA400x_MAX_PACKET_LEN);
  } else {
    tx_buf = custom_alloc (len);
  }

  if (ip != NULL) {
    if (ip_len == 4U) {
      to_addr.addr.sin_family   = ATH_AF_INET;
      to_addr.addr.sin_port     = port;
      to_addr.addr.sin_addr     = A_CPU2BE32(__UNALIGNED_UINT32_READ(ip));
      to_addr_len               = sizeof(SOCKADDR_T);
    } else {
      to_addr.addr6.sin6_family = ATH_AF_INET6;
      to_addr.addr6.sin6_port   = port;
      memcpy((void *)&to_addr.addr6.sin6_addr, (void *)ip, ip_len);
      to_addr_len               = sizeof(SOCKADDR_6_T);
    }
  }

  len_to_send = (int32_t)len;
  len_sent    = 0U;
  if (tx_buf != NULL) {
    do {
      len_curr = len_to_send - len_sent;
      if (len_curr > WIFI_QCA400x_MAX_PACKET_LEN) {
        len_curr = WIFI_QCA400x_MAX_PACKET_LEN;
      }
      memcpy((void *)tx_buf, (const void *)((const char *)buf + len_sent), len_curr);
      if (ip != NULL) {
        ret = qcom_sendto(socket_arr[socket].handle, tx_buf, (int32_t)len, 0, (struct sockaddr *)&to_addr, to_addr_len);
      } else {
        ret = qcom_send  (socket_arr[socket].handle, tx_buf, (int32_t)len_to_send, 0);
      }
      if (ret > 0) {
        len_sent += ret;
      } else if (ret < 0) {
        // If error
        ret = ARM_SOCKET_ERROR;
        break;
      }
    } while (len_to_send > len_sent);
    if (tx_buf != NULL) {
      custom_free(tx_buf);
    }
  } else {
    ret = ARM_SOCKET_ERROR;
  }

  if (ret > 0) {
    ret = len_sent;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_SocketGetSockName (int32_t socket, uint8_t *ip, uint32_t *ip_len, uint16_t *port)
  \brief         Retrieve local IP address and port of a socket.
  \param[in]     socket   Socket identification number
  \param[out]    ip       Pointer to buffer where local address shall be returned (NULL for none)
  \param[in,out] ip_len   Pointer to length of 'ip' (or NULL if 'ip' is NULL)
                   - length of supplied 'ip' on input
                   - length of stored 'ip' on output
  \param[out]    port     Pointer to buffer where local port shall be returned (NULL for none)
  \return        status information
                   - 0                            : Operation successful
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument (pointer to buffer or length)
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketGetSockName (int32_t socket, uint8_t *ip, uint32_t *ip_len, uint16_t *port) {
  int32_t  ret, dummy_i32;
  uint32_t u32, dummy_u32;
  uint8_t  dummy_ip6[16];

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if (((ip != NULL) && (ip_len == NULL)) || ((ip_len != NULL) && (*ip_len < socket_arr[socket].ip_len))) {
    return ARM_SOCKET_EINVAL;
  }
  if ((socket_arr[socket].local_port == 0U) && (socket_arr[socket].remote_port == 0U)) {
    // Not connected and not bound
    return ARM_SOCKET_EINVAL;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  ret = 0;

  *ip_len = socket_arr[socket].ip_len;

  // Get local IP
  if (ip != NULL) {
    if ((socket_arr[socket].local_port != 0U)) {
      *port = socket_arr[socket].local_port;
      memcpy((void *)ip, socket_arr[socket].local_ip, *ip_len);
    } else {
      if (socket_arr[socket].ip_len == 4U) {
        if (qcom_ipconfig(0, IPCFG_QUERY, &u32, &dummy_u32, &dummy_u32) == A_OK) {
          __UNALIGNED_UINT32_WRITE(ip, A_CPU2BE32(u32));
        } else {
          ret = ARM_SOCKET_ERROR;
        }
      } else {
        if (qcom_ip6_address_get(0, (uint8_t *)ip, dummy_ip6, dummy_ip6, dummy_ip6, &dummy_i32, &dummy_i32, &dummy_i32, &dummy_i32) != A_OK) {
          ret = ARM_SOCKET_ERROR;
        }
      }
    }
  }

  // Get local port
  if ((ret == 0) && (port != NULL)) {
    *port = socket_arr[socket].local_port;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_SocketGetPeerName (int32_t socket, uint8_t *ip, uint32_t *ip_len, uint16_t *port)
  \brief         Retrieve remote IP address and port of a socket
  \param[in]     socket   Socket identification number
  \param[out]    ip       Pointer to buffer where remote address shall be returned (NULL for none)
  \param[in,out] ip_len   Pointer to length of 'ip' (or NULL if 'ip' is NULL)
                   - length of supplied 'ip' on input
                   - length of stored 'ip' on output
  \param[out]    port     Pointer to buffer where remote port shall be returned (NULL for none)
  \return        status information
                   - 0                            : Operation successful
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument (pointer to buffer or length)
                   - ARM_SOCKET_ENOTCONN          : Socket is not connected
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketGetPeerName (int32_t socket, uint8_t *ip, uint32_t *ip_len, uint16_t *port) {
  uint32_t u32;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if (((ip != NULL) && (ip_len == NULL)) || ((ip_len != NULL) && (*ip_len < socket_arr[socket].ip_len))) {
    return ARM_SOCKET_EINVAL;
  }
  if (socket_arr[socket].remote_port == 0) {
    return ARM_SOCKET_ENOTCONN;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  // Get remote host IP
  if (ip != NULL) {
    if (socket_arr[socket].ip_len == 4U) {
      u32 = *((uint32_t *)socket_arr[socket].remote_ip);
      __UNALIGNED_UINT32_WRITE(ip, A_CPU2BE32(u32));
    } else {
      memcpy((void *)ip, (void *)socket_arr[socket].remote_ip, *ip_len);
    }
    *ip_len = socket_arr[socket].ip_len;
  }

  // Get remote host port
  if (port != NULL) {
    *port = socket_arr[socket].remote_port;
  }

  return 0;
}

/**
  \fn            int32_t WiFi_SocketGetOpt (int32_t socket, int32_t opt_id, void *opt_val, uint32_t *opt_len)
  \brief         Get socket option.
  \param[in]     socket   Socket identification number
  \param[in]     opt_id   Option identifier
  \param[out]    opt_val  Pointer to the buffer that will receive the option value
  \param[in,out] opt_len  Pointer to length of the option value
                   - length of buffer on input
                   - length of data on output
  \return        status information
                   - 0                            : Operation successful
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument
                   - ARM_SOCKET_ENOTSUP           : Operation not supported
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketGetOpt (int32_t socket, int32_t opt_id, void *opt_val, uint32_t *opt_len) {
  int32_t ret;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if ((opt_val == NULL) || (opt_len == NULL) || (*opt_len < 4U)) {
    return ARM_SOCKET_EINVAL;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  ret = 0;

  switch (opt_id) {
    case ARM_SOCKET_SO_RCVTIMEO:
      __UNALIGNED_UINT32_WRITE(opt_val, socket_arr[socket].recv_timeout);
      *opt_len = 4U;
      break;

    case ARM_SOCKET_SO_TYPE:
      __UNALIGNED_UINT32_WRITE(opt_val, socket_arr[socket].type);
      *opt_len = 4U;
      break;
    case ARM_SOCKET_SO_SNDTIMEO:
      // Not supported through QCOM API
    case ARM_SOCKET_SO_KEEPALIVE:
      // Not supported through QCOM API
      ret = ARM_SOCKET_ENOTSUP;
      break;
    default:
      ret = ARM_SOCKET_EINVAL;
      break;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_SocketSetOpt (int32_t socket, int32_t opt_id, const void *opt_val, uint32_t opt_len)
  \brief         Set socket option.
  \param[in]     socket   Socket identification number
  \param[in]     opt_id   Option identifier
  \param[in]     opt_val  Pointer to the option value
  \param[in]     opt_len  Length of the option value in bytes
  \return        status information
                   - 0                            : Operation successful
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EINVAL            : Invalid argument
                   - ARM_SOCKET_ENOTSUP           : Operation not supported
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketSetOpt (int32_t socket, int32_t opt_id, const void *opt_val, uint32_t opt_len) {
  int32_t  ret;
  uint32_t u32;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if ((opt_val == NULL) || (opt_len == NULL) || (opt_len != 4U)) {
    return ARM_SOCKET_EINVAL;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  ret = 0;

  u32 = __UNALIGNED_UINT32_READ(opt_val);
  switch (opt_id) {
    case ARM_SOCKET_IO_FIONBIO:
      socket_arr[socket].non_blocking = u32;
      break;
    case ARM_SOCKET_SO_RCVTIMEO:
      socket_arr[socket].recv_timeout = u32;
      break;
    case ARM_SOCKET_SO_SNDTIMEO:
      // Not supported through QCOM API
    case ARM_SOCKET_SO_KEEPALIVE:
      // Not supported through QCOM API
      ret = ARM_SOCKET_ENOTSUP;
    default:
      ret = ARM_SOCKET_EINVAL;
      break;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_SocketClose (int32_t socket)
  \brief         Close and release a socket.
  \param[in]     socket   Socket identification number
  \return        status information
                   - 0                            : Operation successful
                   - ARM_SOCKET_ESOCK             : Invalid socket
                   - ARM_SOCKET_EAGAIN            : Operation would block (may be called again)
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketClose (int32_t socket) {
  int32_t ret = 0;

  if ((socket < 0) || (socket >= MAX_SOCKETS_SUPPORTED) || (socket_arr[socket].handle == 0)) {
    return ARM_SOCKET_ESOCK;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  qcom_socket_close(socket_arr[socket].handle);
  socket_arr[socket].handle = 0;

  return ret;
}

/**
  \fn            int32_t WiFi_SocketGetHostByName (const char *name, int32_t af, uint8_t *ip, uint32_t *ip_len)
  \brief         Retrieve host IP address from host name.
  \param[in]     name     Host name
  \param[in]     af       Address family
  \param[out]    ip       Pointer to buffer where resolved IP address shall be returned
  \param[in,out] ip_len   Pointer to length of 'ip'
                   - length of supplied 'ip' on input
                   - length of stored 'ip' on output
  \return        status information
                   - 0                            : Operation successful
                   - ARM_SOCKET_EINVAL            : Invalid argument
                   - ARM_SOCKET_ENOTSUP           : Operation not supported
                   - ARM_SOCKET_ETIMEDOUT         : Operation timed out
                   - ARM_SOCKET_EHOSTNOTFOUND     : Host not found
                   - ARM_SOCKET_ERROR             : Unspecified error
*/
static int32_t WiFi_SocketGetHostByName (const char *name, int32_t af, uint8_t *ip, uint32_t *ip_len) {
  int32_t    ret;
  SOCKADDR_T dns_ip;
  SOCKADDR_T ip_addr;
  uint32_t   dns_servers[2];
  uint32_t   dns_servers_num;

  if (af == ARM_SOCKET_AF_INET6) {
    // IPv6 resolver currently not supported as qcom_dnsc_get_host_by_name and 
    // qcom_dnsc_get_host_by_name2 do not support long host addresses 
    // (more than 32 characters) and qcom_dns_resolver only supports IPv4 addresses
    return ARM_SOCKET_ENOTSUP;
  }
  if (af != ARM_SOCKET_AF_INET) {
    return ARM_SOCKET_EINVAL;
  }
  if ((name == NULL) || (ip == NULL) || (ip_len == NULL) || (*ip_len < 4U)) {
    return ARM_SOCKET_EINVAL;
  }
  if (driver_initialized == 0U) {
    return ARM_SOCKET_ERROR;
  }

  ret = 0;

  memset((void *)dns_servers, 0, sizeof(dns_servers));
  dns_servers_num = 0U;
  qcom_dns_server_address_get(dns_servers, &dns_servers_num);

  dns_ip.sin_addr = A_CPU2BE32(dns_servers[0]);
  if (qcom_dns_resolver(dns_ip, (char *)name, &ip_addr, WIFI_QCA400x_DNS_RESOLVE_TIMEOUT) == A_OK) {
    __UNALIGNED_UINT32_WRITE(ip, ip_addr.sin_addr);
  } else {
    ret = ARM_SOCKET_ERROR;
  }

  return ret;
}

/**
  \fn            int32_t WiFi_Ping (const uint8_t *ip, uint32_t ip_len)
  \brief         Probe remote host with Ping command.
  \param[in]     ip       Pointer to remote host IP address
  \param[in]     ip_len   Length of 'ip' address in bytes
  \return        execution status
                   - ARM_DRIVER_OK                : Operation successful
                   - ARM_DRIVER_ERROR             : Operation failed
                   - ARM_DRIVER_ERROR_TIMEOUT     : Timeout occurred
                   - ARM_DRIVER_ERROR_UNSUPPORTED : Operation not supported
                   - ARM_DRIVER_ERROR_PARAMETER   : Parameter error (NULL ip pointer or ip_len different than 4 or 16)
*/
static int32_t WiFi_Ping (const uint8_t *ip, uint32_t ip_len) {
  int32_t ret;

  if ((ip == NULL) || ((ip_len != 4U) && (ip_len != 16U))) {
    return ARM_DRIVER_ERROR_PARAMETER;
  }
  if (driver_initialized == 0U) {
    return ARM_DRIVER_ERROR;
  }

  ret = ARM_DRIVER_OK;

  switch (ip_len) {
    case 4:
      if (qcom_ping(A_CPU2BE32(__UNALIGNED_UINT32_READ(ip)), 1U) != A_OK) {
        ret = ARM_DRIVER_ERROR;
      }
      break;
    case 16:
      if (qcom_ping6((QOSAL_UINT8 *)ip, 1U) != A_OK) {
        ret = ARM_DRIVER_ERROR;
      }
      break;
    default:
      ret = ARM_DRIVER_ERROR_UNSUPPORTED;
      break;
  }

  return ret;
}
#endif


// Structure exported by driver Driver_WiFin (default: Driver_WiFi0)

extern
ARM_DRIVER_WIFI ARM_Driver_WiFi_(WIFI_QCA400x_DRV_NUM);
ARM_DRIVER_WIFI ARM_Driver_WiFi_(WIFI_QCA400x_DRV_NUM) = { 
  WiFi_GetVersion,
  WiFi_GetCapabilities,
  WiFi_Initialize,
  WiFi_Uninitialize,
  WiFi_PowerControl,
  WiFi_GetModuleInfo,
  WiFi_SetOption,
  WiFi_GetOption,
  WiFi_Scan,
  WiFi_Activate,
  WiFi_Deactivate,
  WiFi_IsConnected,
  WiFi_GetNetInfo,
#if (WIFI_QCA400x_MODE_INT_STACK)       // If Internal Network Stack mode is compile-time selected
  NULL,
  NULL,
  NULL,
  NULL,
  WiFi_SocketCreate,
  WiFi_SocketBind,
  WiFi_SocketListen,
  WiFi_SocketAccept,
  WiFi_SocketConnect,
  WiFi_SocketRecv,
  WiFi_SocketRecvFrom,
  WiFi_SocketSend,
  WiFi_SocketSendTo,
  WiFi_SocketGetSockName,
  WiFi_SocketGetPeerName,
  WiFi_SocketGetOpt,
  WiFi_SocketSetOpt,
  WiFi_SocketClose,
  WiFi_SocketGetHostByName,
  WiFi_Ping
#else                                   // If Bypass or Pass-through mode is compile-time selected
  WiFi_BypassControl,
  WiFi_EthSendFrame,
  WiFi_EthReadFrame,
  WiFi_EthGetRxFrameSize,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
#endif
};

/**
 * @ingroup     Examples
 * @{
 *
 * @file        esp32_blinker_client.c
 * @brief       This is an iotivity client on an esp32 platform. It sends a PUT request when the
 *              button is pressed to an IoTivity device that has an /plug/1 resource.
 *
 * @author       
 *
 * @}
 */

#include <stdio.h>
#include <pthread.h>
#include <string.h>
 #include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "nvs.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "tcpip_adapter.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_vfs_dev.h"

#include "oc_api.h"
#include "port/oc_clock.h"
#include "debug_print.h"
#include "api/oc_events.h"
#include "config.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "plug.h"


#define NUM_LIGHTS 3
/**< variables for multithreading */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static struct timespec ts;

static bool quit = 0;
static int client_status, server_status;
static pid_t client_pid, server_pid;
static bool plugs = false;

/**< Constants used for getting IP */
static const int IPV4_CONNECTED_BIT = BIT0;
static const int IPV6_CONNECTED_BIT = BIT1;
static const char *TAG = "iotivity client blinker";
static EventGroupHandle_t wifi_event_group;

#define EXAMPLE_ESP_WIFI_MODE_AP   CONFIG_ESP_WIFI_MODE_AP                    /**< TRUE:AP FALSE:STA */
#define EXAMPLE_WIFI_SSID CONFIG_WIFI_SSID
#define EXAMPLE_WIFI_PASS CONFIG_WIFI_PASSWORD
#define EXAMPLE_MAX_STA_CONN 60

#define MAX_URI_LENGTH (30)
#define OC_CLIENT 1
static char light_1[MAX_URI_LENGTH];
static oc_endpoint_t *plug_server;
static bool plug_state = false;
static bool g_wifi_reconnect_flag = true;

/**< BUTTON MANAGE PINS*/
#define GPIO_INPUT_IO_1     0       /**< Integrated Button pin */

static int
app_init(void)
{
  int ret = oc_init_platform("Intel Corporation", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.wk.d", "Generic Client", "ocf.1.0.0",
                       "ocf.res.1.3.0", NULL, NULL);
  return ret;
}

/**
 * function made to stop observation of devices
 */
static oc_event_callback_retval_t
stop_observe(void *data)
{
  (void)data;
  PRINT("Stopping OBSERVE\n");
  oc_stop_observe(light_1, plug_server);
  return OC_EVENT_DONE;
}

/*********** common ***************/

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void
handle_signal(int signal)
{
  (void)signal;
  quit = true;
  signal_event_loop();
}

static void
post_plug(oc_client_response_t *data){
  PRINT("PLUG_STATUS: \n");
  if(data->code==OC_STATUS_CHANGED){
    PRINT("STATUS CHANGED\n");
  }else{
    PRINT("RESPONSE IS %d\n",data->code);
  }
}


/**
 * Check if resource exist
 */
static void
check_resource_cb(oc_client_response_t *data)
{
  static int count = 0;
  bool light = *(bool *)data->user_data;

  for (oc_rep_t *rep = data->payload; rep; rep = rep->next) {
    switch (rep->type) {
      case OC_REP_BOOL:
        if (light != rep->value.boolean)
          exit(EXIT_FAILURE);
        break;
      default:
        exit(EXIT_FAILURE);
    }
  }

  count++;
  if (count >= NUM_LIGHTS) {
    quit = true;
    signal_event_loop();
  }
}

/**
 *   
 */
static void
observe_plug(oc_client_response_t *data){
  PRINT("OBSERVING PLUG\n");
   oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    PRINT("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      PRINT("%d\n", rep->value.boolean);
      plugs = rep->value.boolean;
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  if(oc_init_post(light_1, plug_server, NULL, &post_plug, LOW_QOS, NULL)){
      oc_rep_start_root_object();
      oc_rep_set_boolean(root, state, plug_state);
      oc_rep_end_root_object();
      PRINT("DOING POST\n");
  
    if(oc_do_post()){
      PRINT("SENT SIGNAL\n");
    }else{
      PRINT("YOU REPOSTED TO THE WRONG NEIGHBORHOOD\n");
    }
  }else{
    PRINT("CANNOT init POST\n");
  }
}

/**
 * handler thar looks on the red an make a discovery request
 * for a device with an URI in this especific
 * case an URI of type oic.r.plug
 * If it is found later on do a GET request to look for the device status
 */ 
static oc_discovery_flags_t
discovery_cb(const char *di, const char *uri, oc_string_array_t types,
             oc_interface_mask_t interfaces, oc_endpoint_t *server,
             oc_resource_properties_t bm, void *user_data)
{
  (void)bm;
  (void)di;
  (void)interfaces;
  (void)user_data;
  int uri_len = strlen(uri);
  int i;
  static int pos = 0;
  PRINT("ID del device %s\n", di);
  uri_len = (uri_len>=MAX_URI_LENGTH)? MAX_URI_LENGTH-2:uri_len;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    int ret;
    char *rt = oc_string_array_get_item(types, i);

    if (strlen(rt) == 10 && strncmp(rt, "oic.r.plug", 10) == 0){
      strncpy(light_1,uri,uri_len);
      light_1[uri_len]='\0';
      plug_server = server; 
      PRINT("Resource %s hosted at endpoints:\n", light_1);
      oc_endpoint_t *endo = server;
      while(endo!=NULL){
        PRINTipaddr(*endo);
        PRINT("\n");
        endo = endo->next;
    }
    
    oc_do_observe(light_1, plug_server, NULL, &observe_plug, LOW_QOS, NULL);
    oc_set_delayed_callback(NULL, &stop_observe, 15);
    PRINT("Get response values of %s al endpoint:\n",light_1);
    pos++;
    return OC_STOP_DISCOVERY;
    }
  }
  oc_free_server_endpoints(server);
  return OC_CONTINUE_DISCOVERY;
}

/**
 * Function to do a request using an uri on representation of a device
 */
static void
issue_request(void)
{
  oc_do_ip_discovery("oic.r.plug", &discovery_cb, NULL);
}

/**
 * Populate standard OCF resources (platform/device)
 */
static int
app_init_client(void)
{
  int ret;

  ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.wk.d", "Client Test", "ocf.1.0.0", 
  "ocf.1.0.0", NULL, NULL);

  return ret;
}

/**
 * Event handler use for wifi connection
 */ 
static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        printf("1Client Started");
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        ESP_LOGI(TAG, "got ip:%s",
                 ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
        xEventGroupSetBits(wifi_event_group, IPV4_CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_AP_STACONNECTED:
        ESP_LOGI(TAG, "station:"MACSTR" join, AID=%d",
                 MAC2STR(event->event_info.sta_connected.mac),
                 event->event_info.sta_connected.aid);
        break;
    case SYSTEM_EVENT_AP_STADISCONNECTED:
        ESP_LOGI(TAG, "station:"MACSTR"leave, AID=%d",
                 MAC2STR(event->event_info.sta_disconnected.mac),
                 event->event_info.sta_disconnected.aid);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        ESP_LOGI(TAG, "disconnected");
        if (g_wifi_reconnect_flag) {
            ESP_LOGI(TAG, "reconnect again");
            esp_wifi_connect();
        }
        xEventGroupClearBits(wifi_event_group, IPV4_CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

/**
 * Main Function that is to be executed by a Task  
 */
static int blinker_main(void)
{
    int init;
    tcpip_adapter_ip_info_t ip4_info = { 0 };
    struct ip6_addr if_ipaddr_ip6 = { 0 };
    ESP_LOGI(TAG, "iotivity blinker client task started");
    /**< wait to fetch IPv4 && ipv6 address */
#ifdef OC_IPV4
    xEventGroupWaitBits(wifi_event_group, IPV4_CONNECTED_BIT, false, true, portMAX_DELAY);
#else
    xEventGroupWaitBits(wifi_event_group, IPV4_CONNECTED_BIT | IPV6_CONNECTED_BIT, false, true, portMAX_DELAY);
#endif

    if ( tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip4_info) != ESP_OK) {
        print_error("get IPv4 address failed");
    } else {
        ESP_LOGI(TAG, "got IPv4 addr:%s", ip4addr_ntoa(&(ip4_info.ip)));
    }

#ifndef OC_IPV4
    if ( tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipaddr_ip6) != ESP_OK) {
        print_error("get IPv6 address failed");
    } else {
        ESP_LOGI(TAG, "got IPv6 addr:%s", ip6addr_ntoa(&if_ipaddr_ip6));
    }
#endif

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .requests_entry = issue_request };
  oc_clock_time_t next_event;

#ifdef OC_SECURITY
  oc_storage_config("./client_creds");                      /**< defined in the implementation of the storage interface for a target */
#endif                                                      /* OC_SECURITY */
  oc_set_con_res_announced(false);
  init = oc_main_init(&handler);
  if (init < 0)
    return init;
  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }

  oc_main_shutdown();
  return 0;
}

/**
 * Function to get wireless connection
 */
static void initialise_wifi(void)
{
    tcpip_adapter_init();

    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));
    wifi_config_t wifi_config;
    memset(&wifi_config, 0, sizeof(wifi_config));
    memcpy(wifi_config.sta.password, EXAMPLE_WIFI_PASS, strlen(EXAMPLE_WIFI_PASS));
    memcpy(wifi_config.sta.ssid, EXAMPLE_WIFI_SSID, strlen(EXAMPLE_WIFI_SSID)); 
    int i; 
    for(i=strlen(EXAMPLE_WIFI_SSID); i<32; i++) { wifi_config.sta.ssid[i] = '\0'; } 
    for(i=strlen(EXAMPLE_WIFI_PASS); i<64; i++) { wifi_config.sta.password[i] = '\0'; } 
       
    ESP_LOGI(TAG, "wifi_init_sta stop sta");
    ESP_ERROR_CHECK(esp_wifi_stop() );
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}


/******************APP_MAIN*********************************/

/**
 * Main Function that is executed in which are setted task 
 */
 void app_main(void)
{
    esp_err_t n = nvs_flash_init();
    if (n != ESP_OK){
        print_error("nvs_flash_init failed");
        ESP_ERROR_CHECK(nvs_flash_erase());
        n = nvs_flash_init();
    }
    ESP_ERROR_CHECK(n);

    pthread_cond_init(&cv, NULL);

    print_macro_info();
    
    initialise_wifi();

    if ( xTaskCreate(&blinker_main, "blinker_main", 15*1024, NULL, 5, NULL) != pdPASS ) {
        print_error("task create failed");
    }
    button_event_t ev;
    QueueHandle_t button_events = button_init(PIN_BIT(GPIO_INPUT_IO_1));
    while (true) {
        if (xQueueReceive(button_events, &ev, 1000/portTICK_PERIOD_MS)) {
            if ((ev.pin == GPIO_INPUT_IO_1) && (ev.event == BUTTON_DOWN)) {
                plug_state = !plug_state;
                PRINT("Estado del boton: %x\n",plug_state );
            }

        }
    }
}
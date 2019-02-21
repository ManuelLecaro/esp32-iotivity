/**
 * Brief:
 * Demo inteligent plug controller created based on iotivity server  
 * which has a resource located on /plug/1
 * GPIO configuration:
 * GPIO20: output
 * GPIO21: output
 * GPIO4:  input, pulled up, interrupt from rising edge and falling edge
 * GPIO5:  input, pulled up, interrupt from rising edge.
 **/


#include "oc_api.h"
#include "port/oc_clock.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "nvs.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "debug_print.h"
#include "esp_err.h"
#include "security/oc_svr.h"
#include "security/oc_tls.h"
#include "api/oc_events.h"
#include "config.h"
#include "security/oc_acl.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "security/oc_cred.h"
#include "security/oc_pstat.h"
#include "oc_introspection.h"
#include <driver/dac.h>

#include "driver/adc.h"
#include "esp_adc_cal.h"

#include <inttypes.h>

/*********Initialization of POSIX SEMAPHORES***********/
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static bool quit, plugs = false;

/*******Variables used for server&client conections***********/
static int client_status, server_status;
static EventGroupHandle_t wifi_event_group;
static const int IPV4_CONNECTED_BIT = BIT0;
static const int IPV6_CONNECTED_BIT = BIT1;

/*******Definitions for WIFI use on STA and AP modes************/
#define EXAMPLE_ESP_WIFI_MODE_AP   CONFIG_ESP_WIFI_MODE_AP 
#define EXAMPLE_WIFI_SSID CONFIG_WIFI_SSID
#define EXAMPLE_WIFI_PASS CONFIG_WIFI_PASSWORD
#define EXAMPLE_MAX_STA_CONN 60

static const char *TAG = "blinker server";
static bool g_wifi_reconnect_flag = true;

/******SETTING TEMPORAL ID FOR RECOGNITION*******/
static const char* PROTO_INDEP_ID = "b0ed9259-ec95-4ac6-8f62-241d0da02683";

/****Definitions use for GPIO manage***/
static xQueueHandle gpio_evt_queue = NULL;

/******Setting up General purpose input/output***************/
#define GPIO_OUTPUT_IO_0    19                          /**< PIN TO TURN ON/OFF RELAY */                
#define GPIO_OUTPUT_IO_1    21
#define GPIO_OUTPUT_PIN_SEL  ((1ULL<<GPIO_OUTPUT_IO_0) | (1ULL<<GPIO_OUTPUT_IO_1))
#define GPIO_INPUT_IO_0     4
#define GPIO_INPUT_IO_1     5
#define GPIO_INPUT_PIN_SEL  ((1ULL<<GPIO_INPUT_IO_0) | (1ULL<<GPIO_INPUT_IO_1))
#define ESP_INTR_FLAG_DEFAULT 0

/***Setting device for ADC manage**/
static adc_channel_t canal = ADC1_CHANNEL_6;
static const adc_atten_t atten = ADC_ATTEN_0db;
static const adc_unit_t unit = ADC_UNIT_1;

/**
 * Checks if ADC calibration values are burned into eFuse 
 * checks if ADC reference voltage or Two Point values have been burned 
 * to the eFuse of the current ESP32
 */
static void check_efuse(){
  if(esp_adc_cal_check_efuse(ESP_ADC_CAL_VAL_EFUSE_TP)==ESP_OK){
    printf("message efuse 2 point supported\n");
  }else{
    printf("efuse 2 pt not supported\n");
  }
  if(esp_adc_cal_check_efuse(ESP_ADC_CAL_VAL_DEFAULT_VREF)==ESP_OK){
    printf("Efuse Vref supported\n");
  }else{
    printf("Efuse Vref not supported\n");
  }
}

/**
 * Configure ADC1 capture width and setting its attenuation
 * otherwise if the channel is ADC2 the same operations are performed
 */
static void set_adc(){
  check_efuse();
  if(unit==ADC_UNIT_1){
    adc1_config_width(ADC_WIDTH_BIT_12);
    adc1_config_channel_atten(canal, atten);
  }else{
    adc2_config_channel_atten((adc2_channel_t)canal, atten);
  }
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
  signal_event_loop();
  quit = 1;
}

/**
 * Disabling interrupts and configuring pins as output mode to set on
 * input mode
 */
static void 
configuration_set(){
  gpio_config_t config;
  config.intr_type = GPIO_PIN_INTR_DISABLE;                 /**< disable interrupt */
  config.mode = GPIO_MODE_OUTPUT;                           /**< set as output mode */
  config.pin_bit_mask = GPIO_OUTPUT_PIN_SEL;                /**< bit mask of the pins that you want to set,e.g.GPIO20/21 */
  config.pull_down_en = 0;                                  /**< disable pull-down mode */
  config.pull_up_en = 0;                                    /**< disable pull-up mode */
  gpio_config(&config);                                     /**< configure GPIO with the given settings */
  config.intr_type = GPIO_PIN_INTR_POSEDGE;                 /**< interrupt of rising edge */
  config.pin_bit_mask = GPIO_INPUT_PIN_SEL;                 /**< bit mask of the pins, use GPIO4/5 here */
  config.mode = GPIO_MODE_INPUT;                            /**< set as input mode */    
  config.pull_up_en = 1;                                    /**< enable pull-up mode */
   gpio_config(&config);
}

/**
 * Task used to check the current level of the configured pins on the GPIO 
 */
static void gpio_manage(void* arg)
{
    uint32_t io_num;
    for(;;) {
        if(xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
            printf("GPIO[%d] intr, val: %d\n", io_num, gpio_get_level(io_num));
        }
    }
}

/***CONNECT OR DISCONNECT THE PLUG ACCORDING TO THE STATE***/
/***Setting correctly bias the inputs of digital gates 
* to stop them from floating about randomly when 
* there is no input condition***/
static void 
manage_plug_up_down(bool state){

  if(state){
    ESP_ERROR_CHECK(gpio_set_level(GPIO_OUTPUT_IO_0,(uint32_t)1));
    PRINT("CHANGING PLUG\n");
  }else{
    ESP_ERROR_CHECK(gpio_set_level(GPIO_OUTPUT_IO_0,(uint32_t)0));
    PRINT("NO CHANGES ON PLUG\n");
  }
    
}

/**
 * Control and configure GPIO used in case is added an option to
 * control voltage output on the plug
*/
static void
manage_plug_adc(double voltage){

  gpio_config_t config;
  config.intr_type = GPIO_PIN_INTR_DISABLE;                     /**< disable interrupt */

  config.mode = GPIO_MODE_OUTPUT;                               /**< set as output mode */
  
  config.pin_bit_mask = GPIO_OUTPUT_PIN_SEL;                    /**< bit mask of the pins that you want to set,e.g.GPIO20/21 */

  config.pull_down_en = 0;                                      /**< disable pull-down mode */

  config.pull_up_en = 0;                                        /**< disable pull-up mode */

  gpio_config(&config);                                         /**< configure GPIO with the given settings */

  dac_output_enable(DAC_CHANNEL_1);                             /**< GPIO_32 */
  dac_output_voltage(DAC_CHANNEL_1, voltage);

}


/*********** Iotivity server ***************/

/**
 * Function set to create custom properties for a device 
 */
static void
set_device_custom_property(void *data)
{
  (void)data;
  oc_set_custom_device_property(purpose, "smart plug");
  oc_set_custom_device_property(piid, PROTO_INDEP_ID);
}

/**
 * Init the instrospection of the platform and device, setting the name
 * of the device 
 */
static int
app_init(void)
{
  int r = oc_init_platform("Intel", NULL, NULL);
  if (r != 0)
    return r;

  r |=  oc_add_device("/oic/d", "oic.d.plug", "Left Wall", "ocf.1.0.0",
      "ocf.res.1.0.0", set_device_custom_property, NULL);
  oc_str_to_uuid(PROTO_INDEP_ID,oc_core_get_device_id(r));
  
  return r;
}

/**
 * Handler for get requests 
 * 
 */
static void
get_plug(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  oc_rep_start_root_object();
  PRINT("GET_plug_state request:\n");
  switch (interface) {
    case OC_IF_BASELINE:
      oc_process_baseline_interface(request->resource);
    case OC_IF_RW:
      oc_rep_set_boolean(root, state, plugs);
      break;
    default:
      break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
  PRINT("Plug state %d\n", plugs);
}

/**
 * Handler for post requests 
 */
static void
post_plug(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  (void)interface;
  PRINT("POST PLUG'S STATE:\n");
  bool state = false;
  double voltage = 0;
  oc_rep_t *res = request->request_payload;

  while(res!=NULL){
    switch(res->type){
    case OC_REP_BOOL:                     //order to plugin or plugout
      state = res->value.boolean;
      PRINT("ON/OFF PLUG VALUE: %d\n", state);
      manage_plug_up_down(state);
      //vTaskDelay(50);
      break;
    case OC_REP_INT:
      voltage = res->value.double_p;
      PRINT("SETTING PLUG'S VOLTAGE\n");
      manage_plug_adc(voltage);
      vTaskDelay(50);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    res=res->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  plugs =state;

}

/**
 * Handler for put requests 
 */
static void
put_plug(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  post_plug(request, interface, user_data);
}

/**
 * Registering of resources that the IoTivity server post, setting of 
 * the URI that responses to REST request and its handlers 
 */
static void
register_resources(void)
{

    oc_resource_t *res = oc_new_resource("plug","/plug/1",1,0);
    oc_string_t *stringi;
    oc_free_string(&(res->name));
    oc_new_string(&(res->name), PROTO_INDEP_ID, strlen(PROTO_INDEP_ID));
    oc_resource_bind_resource_type(res, "oic.r.switch.binary");
    oc_resource_bind_resource_interface(res, OC_IF_RW);
    oc_resource_set_default_interface(res, OC_IF_RW);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_observable(res,true);
    oc_resource_set_periodic_observable(res, 1);
    oc_resource_set_request_handler(res, OC_GET, get_plug, NULL);
    oc_resource_set_request_handler(res,OC_POST,post_plug, NULL);
    oc_resource_set_request_handler(res,OC_PUT, put_plug, NULL);
    oc_add_resource(res);
  }


/**
 * Function use as handler to control Server operations
 */
static int
start_server(void)
{

  /*Get IPV4 Adress*/
  int init;
  tcpip_adapter_ip_info_t ip4_info = { 0 };
  struct ip6_addr if_ipaddr_ip6 = { 0 };
  ESP_LOGI(TAG, "iotivity server task started");
  xEventGroupWaitBits(wifi_event_group, IPV4_CONNECTED_BIT | IPV6_CONNECTED_BIT, false, true, portMAX_DELAY);
  
  if ( tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip4_info) != ESP_OK) {
      print_error("get IPv4 address failed");
  } else {
      ESP_LOGI(TAG, "got IPv4 addr:%s", ip4addr_ntoa(&(ip4_info.ip)));
  }
  if ( tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipaddr_ip6) != ESP_OK) {
      print_error("get IPv6 address failed");
  } else {
      ESP_LOGI(TAG, "got IPv6 addr:%s", ip6addr_ntoa(&if_ipaddr_ip6));
  }
  int ret;
  static const oc_handler_t handler = {    .init = app_init,
          .signal_event_loop = signal_event_loop,
          .register_resources = register_resources };
  
  oc_clock_time_t  next_event;

  #ifdef OC_SECURITY
  oc_storage_config("./server_creds");
  #endif

  ret = oc_main_init(&handler);
  if (ret < 0)
    return ret;

  pthread_mutex_init(&mutex, NULL);
  pthread_cond_init(&cv, NULL);

  while (quit != true) {
    struct timespec ts;

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
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);

  return 0;
}

/**
 * Event handler use on wifi connection
 */
static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
    case SYSTEM_EVENT_STA_START:
      printf("Server started\n");
        esp_wifi_connect();
        break;

    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, IPV4_CONNECTED_BIT);
        heap_caps_print_heap_info(MALLOC_CAP_32BIT);
        printf("got ip new\n");
        break;

    case SYSTEM_EVENT_STA_DISCONNECTED:
        /**< This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, IPV4_CONNECTED_BIT);
        xEventGroupClearBits(wifi_event_group, IPV6_CONNECTED_BIT);
        break;

    case SYSTEM_EVENT_STA_CONNECTED:
        tcpip_adapter_create_ip6_linklocal(TCPIP_ADAPTER_IF_STA);
        printf("link local\n");
        break;

    case SYSTEM_EVENT_GOT_IP6:
        xEventGroupSetBits(wifi_event_group, IPV6_CONNECTED_BIT);
        break;

    default:
        break;
    }

    return ESP_OK;
}


/**
 * Function to get wireless connection
 */
void initialise_wifi(void)
{
    wifi_event_group = xEventGroupCreate();

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    g_wifi_reconnect_flag = true;
    wifi_config_t wifi_config;
    memset(&wifi_config, 0, sizeof(wifi_config));
    memcpy(wifi_config.sta.password, EXAMPLE_WIFI_PASS, strlen(EXAMPLE_WIFI_PASS));
    memcpy(wifi_config.sta.ssid, EXAMPLE_WIFI_SSID, strlen(EXAMPLE_WIFI_SSID)); 
    int i; 
    for(i=strlen(EXAMPLE_WIFI_SSID); i<32; i++) { wifi_config.sta.ssid[i] = '\0'; } 
    for(i=strlen(EXAMPLE_WIFI_PASS); i<64; i++) { wifi_config.sta.password[i] = '\0'; } 

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    vTaskDelay(5000/portTICK_PERIOD_MS);

    ESP_LOGI(TAG, "wifi_init_sta finished.");
    ESP_LOGI(TAG, "connect to ap SSID:%s password:%s",
             EXAMPLE_WIFI_SSID, EXAMPLE_WIFI_PASS);
}

/**
 *  Setting the ESP32 on AP mode 
 */
void wifi_init_softap()
{
    wifi_event_group = xEventGroupCreate();

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = EXAMPLE_WIFI_SSID,
            .ssid_len = strlen(EXAMPLE_WIFI_SSID),
            .password = EXAMPLE_WIFI_PASS,
            .max_connection = EXAMPLE_MAX_STA_CONN,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK
        },
    };
    if (strlen(EXAMPLE_WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_softap finished.SSID:%s password:%s",
             EXAMPLE_WIFI_SSID, EXAMPLE_WIFI_PASS);
}

/******************APP_MAIN*********************************/

/**
 * Main Function that is executed in which are setted task 
 */
void app_main(void)
{
    if (nvs_flash_init() != ESP_OK){
        print_error("nvs_flash_init failed");
    }

    pthread_cond_init(&cv, NULL);

    print_macro_info();

    initialise_wifi();

    configuration_set();

    if ( xTaskCreate(&start_server, "server_main", 15*1024, NULL, 5, NULL) != pdPASS ) {
        print_error("task create failed");
    }
    gpio_evt_queue = xQueueCreate(10, sizeof(uint32_t)); /**< Create a queue to handle gpio event from isr */

    if(xTaskCreate(&gpio_manage, "gpio_task_example", 2048, NULL, 10, NULL)!=pdPASS){                     /**< Start gpio task */
      print_error("pins task created failed\n");
    };

}


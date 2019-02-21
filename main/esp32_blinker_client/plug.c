/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/gpio.h"
#include "esp_log.h"

#include "plug.h"

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#define TAG "PLUGIN"


typedef struct {
    uint8_t pin;
    bool invertido;
    uint16_t historia;
    uint64_t tiempo_bajo;
}rebote_t;

int pin_count = -1;
rebote_t *rebote;
QueueHandle_t queue;

#define MASK 0b1111000000111111

static void update_relay(rebote_t *d){
    d->historia = (d->historia<<1)|gpio_get_level(d->pin);
}

static bool rose_boton(rebote_t *d){
    if((d->historia & MASK)==0b0000000000111111){
        d->historia = 0Xffff;
        return 1;
    }
    return 0;
}

static bool caida_boton(rebote_t *d){
    if((d->historia & MASK)==0b1111000000000000){
        d->historia = 0x0000;
        return 1;
    }
    return 0;
}

static bool boton_up(rebote_t *d){
    if(d->invertido) return caida_boton(d);
    return caida_boton(d);
}

#define LONG_PRESS_DURATION (500)

static uint32_t millis(){
    return esp_timer_get_time()/1000;
}

static void send_event(rebote_t db, int ev){
    button_event_t event = {
        .pin = db.pin,
        .event = ev,
    };
    xQueueSend(queue, &event, portMAX_DELAY);
}

static void button_task(void *pvParameter){

    while(true){
        for(int idx=0;idx<pin_count; idx++){
            update_relay(&rebote[idx]);
            if(rebote[idx].tiempo_bajo && (millis() - rebote[idx].tiempo_bajo >
            LONG_PRESS_DURATION)){
                rebote[idx].tiempo_bajo = 0;
                ESP_LOGI(TAG, "%x LONG", rebote[idx].pin);
                int i = 0;
                while(!boton_up(&rebote[idx])){
                    if (!i) send_event(rebote[idx], BUTTON_DOWN);
                    i++;
                    if (i>=5) i=0;
                    vTaskDelay(10/portTICK_PERIOD_MS);
                    update_relay(&rebote[idx]);
                }
                ESP_LOGI(TAG, "%x UP", rebote[idx].pin);
                send_event(rebote[idx], BUTTON_UP);
            } else if (caida_boton(&rebote[idx])) {
                rebote[idx].tiempo_bajo = 0;                                /**< millis(); */
                ESP_LOGI(TAG, "%x DOWN",rebote[idx].pin);
                send_event(rebote[idx], BUTTON_DOWN);
            } else if (boton_up(&rebote[idx])) {
                rebote[idx].tiempo_bajo = 0;
                ESP_LOGI(TAG, "%x UP", rebote[idx].pin);
                send_event(rebote[idx], BUTTON_UP);               
            }
        }
        vTaskDelay(10/portTICK_PERIOD_MS);
    }

}


QueueHandle_t * button_init(unsigned long long pin_select) {
    if (pin_count != -1) {
        ESP_LOGI(TAG, "Already initialized");
        return NULL;
    }

    /**< Configure the pins */
    gpio_config_t io_conf;
    io_conf.mode = GPIO_MODE_INPUT;
    io_conf.pin_bit_mask = pin_select;
    gpio_config(&io_conf);

    /**< Scan the pin map to determine number of pins */
    pin_count = 0;
    for (int pin=0; pin<=39; pin++) {
        if ((1ULL<<pin) & pin_select) {
            pin_count++;
        }
    }

    /**< Initialize global state and queue */
   rebote = calloc(pin_count, sizeof(rebote_t));
    queue = xQueueCreate(4, sizeof(button_event_t));

    /**< Scan the pin map to determine each pin number, populate the state */
    uint32_t idx = 0;
    for (int pin=0; pin<=39; pin++) {
        if ((1ULL<<pin) & pin_select) {
            ESP_LOGI(TAG, "Registering button input: %x", pin);
            rebote[idx].pin = pin;
            rebote[idx].tiempo_bajo = 0;
            rebote[idx].invertido = true;
            if (rebote[idx].invertido) rebote[idx].historia = 0xffff;
            idx++;
        }
    }

    xTaskCreate(&button_task, "button_task", 4096, NULL, 10, NULL);                 /**< Spawn a task to monitor the pins */

    return queue;
}













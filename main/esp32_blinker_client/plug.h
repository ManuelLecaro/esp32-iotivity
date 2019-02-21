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

#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#ifndef PLUG_H_
#define PLUG_H_

#define PIN_BIT(x) (1ULL<<x)

#define BUTTON_DOWN (1)
#define BUTTON_UP (2)

typedef struct {
	uint8_t pin;                    /**< pin number */                          
    uint8_t event;                  /**< Check ifis UP or Down */
} button_event_t;

QueueHandle_t * button_init(unsigned long long pin_select);

#endif
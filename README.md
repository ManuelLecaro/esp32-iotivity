# Overview
IoTivity is an open source software framework enabling seamless device-to-device connectivity to address the emerging needs of the Internet of Things,for more details, click https://www.iotivity.org  

The demo is the detailed implement of IoTivity based on [IoTivity-constrained](https://github.com/iotivity/iotivity-lite). User can run different features on ESP32 via `make menuconfig`.

**Features List:**  
- support IPv4 OIC server
- support IPv4 OIC client
- support IPv6 OIC server
- support IPv6 OIC client
- support RGB light control
- support TCP
- Added ports for CoAP, CoAPs, CoAP+TCP and CoAPs+TCP
- Secure Connection (incompleted)
- support interact with other IoTivity device

# IoTivity Lite version Updated
Works with current IoTivity version supports OCF 2.0 specifications

# Compiling and flashing the project
Compiling the esp32-iotivity is the same as compiling any other project based on the ESP-IDF:

1. You can clone the total project into an empty directory by using command:
```
git clone https://github.com/espressif/esp32-iotivity.git
cd esp32-iotivity
git submodule update --init --recursive
```
 - make sure that you had cloned all the submodules. The esp32-iotivity project has the `ESP-IDF` and `iotivity-constrained` as the submodule.

2. Set the latest default configuration by `make defconfig`.

3. `make menuconfig` to config your serial port, WiFi ssid and password, IPv4 or IPv6, iotivity server or iotivity client, enable light control or disable light control, and enable or disable debug log. 

 - make sure that your router can support IPv4 multicast and IPv6 multicast.

4. choose two ESP32 board, one as iotivity server, the other as iotivity client, server board connect to the RGB light by `Hardware Introduction`.

5. `make SERVER=1 flash monitor` to compile & flashing & running the server.

6. reconfigure client environment by `make clean && make defconfig && make menuconfig`.

7. `make CLIENT=1 flash monitor` to compile & flashing & running the client.

More details are in the [esp-idf README](https://github.com/espressif/esp-idf/blob/master/README.md).

# SmartPlug Demo
New Demo added that works with two ESP32 one as interruptor(client) and other as the smartplug (server) with GPIO configuration

1. Configure Server Environment with:
    `make menuconfig`
    `select Iotivity Examples Configuration/Blinker Server`
    `make BLINKERSERVER=1 flash monitor` to compile & flashing & running the server
2. Configure Client Environment with:
    `make menuconfig`
    `select Iotivity Examples Configuration/Blinker Client`
    `make BLINKERCLIENT=1 flash monitor` to compile & flashing & running the interruptor

# Codelab Associated to IoTivity on ESP32
The added demos are fully explained in the following codelab [ESP32-IoTivity Codelab](https://manuellecaro.github.io/ESP32-IoTivity/).

More details are in the [esp-idf README](https://github.com/espressif/esp-idf/blob/master/README.md).    


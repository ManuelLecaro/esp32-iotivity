#
# "main" pseudo-component makefile.
#
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)

ifdef CONFIG_IOTIVITY_CLIENT
	COMPONENT_SRCDIRS += esp32_client
endif

ifdef CONFIG_IOTIVITY_SERVER
	COMPONENT_SRCDIRS += esp32_server
endif

ifdef CONFIG_IOTIVITY_CLIENT_BLINKER
	COMPONENT_SRCDIRS += esp32_blinker_client
endif

ifdef CONFIG_IOTIVITY_SERVER_BLINKER
	COMPONENT_SRCDIRS += esp32_blinker_server
endif

COMPONENT_SRCDIRS += esp32_lightbulb

COMPONENT_ADD_INCLUDEDIRS := esp32_lightbulb

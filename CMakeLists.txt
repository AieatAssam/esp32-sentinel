# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32-tbd)

# TinyUSB NCM bounds fix (patches/tinyusb-ncm-ndp-bound.patch) on the managed copy. Runs at every configure:
# a no-op once the patched line is present, otherwise applies the patch and stops if it no longer applies.
set(NCM_SRC "${CMAKE_CURRENT_SOURCE_DIR}/managed_components/espressif__tinyusb")
set(NCM_FILE "${NCM_SRC}/src/class/net/ncm_device.c")
set(NCM_PATCH "${CMAKE_CURRENT_SOURCE_DIR}/patches/tinyusb-ncm-ndp-bound.patch")
if(NOT EXISTS "${NCM_FILE}")
    message(FATAL_ERROR "tinyusb-ncm patch: ${NCM_FILE} not found (component manager has not fetched espressif/tinyusb)")
endif()
file(READ "${NCM_FILE}" NCM_TEXT)
string(FIND "${NCM_TEXT}" "runs past the NTB" NCM_POS)
if(NCM_POS EQUAL -1)
    execute_process(COMMAND patch -p1 --forward --batch -d "${NCM_SRC}" -i "${NCM_PATCH}"
                    RESULT_VARIABLE NCM_RC OUTPUT_VARIABLE NCM_OUT ERROR_VARIABLE NCM_ERR)
    if(NOT NCM_RC EQUAL 0)
        message(FATAL_ERROR "tinyusb-ncm patch does not apply to ${NCM_SRC} (${NCM_RC}): ${NCM_OUT}${NCM_ERR}\n"
                            "Review patches/tinyusb-ncm-ndp-bound.patch against the fetched TinyUSB version.")
    endif()
    message(STATUS "tinyusb-ncm patch applied")
endif()

cmake_minimum_required(VERSION 3.28)
project(esp32_zephyr_pyapi)

find_package(Python COMPONENTS Interpreter REQUIRED)
#execute_process(COMMAND ${Python_EXECUTABLE} -m pip install .. --break-system-packages)
add_custom_target(
    esp32_zephyr_pyapi ALL
    COMMAND pip install ${CMAKE_CURRENT_SOURCE_DIR} --break-system-packages
    COMMENT "Installing Python package"
)

add_custom_target(py_proto
    COMMAND protoc --python_out=${CMAKE_CURRENT_SOURCE_DIR}/src/esp32_zephyr_api/ --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/esp32_zephyr/proto/ cmds.proto
)
add_dependencies(esp32_zephyr_pyapi py_proto)

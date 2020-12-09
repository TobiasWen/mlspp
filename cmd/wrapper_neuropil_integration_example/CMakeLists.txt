set(APP_NAME "wrapper_neuropil_integration_example")

file(GLOB APP_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
set(APP_INCLUDE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(WRAPPER_INCLUDE_PATH  "${PROJECT_SOURCE_DIR}/wrapper/include")
set(NEUROPIL_NAME "neuropil")

add_executable(${APP_NAME} ${APP_SOURCES})
target_include_directories(${APP_NAME} PRIVATE ${WRAPPER_INCLUDE_PATH} ${APP_INCLUDE_PATH})
target_link_libraries(${APP_NAME} ${WRAPPER_NAME} ${NEUROPIL_NAME})

set(APP_NAME "wrapper_example")
set(APP_SRC_PATH "${PROJECT_SOURCE_DIR}/cmd/wrapper_example")

file(GLOB APP_SOURCE_FILES "${APP_SRC_PATH}/*.c")
set(LIB_INCLUDE_PATH  "${PROJECT_SOURCE_DIR}/wrapper/include")
set(APP_SOURCE_FILES ${APP_SOURCE_FILES} PARENT_SCOPE)
set(WRAPPER_NAME "mlspp-c")

message([STATUS] "Dispplaying Directories:")
message([STATUS] "${LIB_INCLUDE_PATH}")
message([STATUS] "${LIBRARY_INCLUDE_PATH}")
message([STATUS] "${OPENSSL_INCLUDE_DIR}")
message([STATUS] "${WRAPPER_NAME}")

add_executable(${APP_NAME} ${APP_SOURCE_FILES})
target_include_directories(${APP_NAME} PRIVATE ${LIB_INCLUDE_PATH}
                                       PRIVATE ${LIBRARY_INCLUDE_PATH}
                                       PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${APP_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${APP_NAME} ${LIB_NAME})
target_link_libraries(${APP_NAME} ${WRAPPER_NAME})

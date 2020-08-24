set(WRAPPER_NAME "mlspp-c")
set(LIB_SRC_PATH "${PROJECT_SOURCE_DIR}/wrapper/src")

file(GLOB LIB_SOURCE_FILES "${LIB_SRC_PATH}/*.cpp")
set(LIB_SOURCE_FILES ${LIB_SOURCE_FILES} PARENT_SCOPE)
set(LIB_INCLUDE_PATH  "${PROJECT_SOURCE_DIR}/wrapper/include")

add_library(${WRAPPER_NAME} ${LIB_SOURCE_FILES})
target_include_directories(${WRAPPER_NAME} PRIVATE ${LIBRARY_INCLUDE_PATH}
                                           PRIVATE ${OPENSSL_INCLUDE_DIR}
                                           PRIVATE ${LIB_INCLUDE_PATH})
target_link_libraries(${WRAPPER_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${WRAPPER_NAME} ${LIB_NAME})
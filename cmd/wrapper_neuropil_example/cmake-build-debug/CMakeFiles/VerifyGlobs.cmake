# CMAKE generated file: DO NOT EDIT!
# Generated by CMake Version 3.17
cmake_policy(SET CMP0009 NEW)

# APP_SOURCES at CMakeLists.txt:3 (file)
file(GLOB NEW_GLOB LIST_DIRECTORIES true "/home/tobias/Projects/mlspp/cmd/wrapper_neuropil_example/src/*.c")
set(OLD_GLOB
  "/home/tobias/Projects/mlspp/cmd/wrapper_neuropil_example/src/arraylist.c"
  "/home/tobias/Projects/mlspp/cmd/wrapper_neuropil_example/src/hashtable.c"
  "/home/tobias/Projects/mlspp/cmd/wrapper_neuropil_example/src/main.c"
  "/home/tobias/Projects/mlspp/cmd/wrapper_neuropil_example/src/np_mls_client.c"
  )
if(NOT "${NEW_GLOB}" STREQUAL "${OLD_GLOB}")
  message("-- GLOB mismatch!")
  file(TOUCH_NOCREATE "/home/tobias/Projects/mlspp/cmd/wrapper_neuropil_example/cmake-build-debug/CMakeFiles/cmake.verify_globs")
endif()
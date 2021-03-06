include(${PROJECT_SOURCE_DIR}/cmake/LoadFileAsVariable.cmake)

aux_source_directory(serializer SERIALIZER_SOURCES)
aux_source_directory(api API_SOURCES)
aux_source_directory(default-src SRC_SOURCES)

include_directories(serializer)
include_directories(interface)
include_directories(default-src)

# Needed to load files as variables
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(pcn-pbforwarder SHARED
  ${SERIALIZER_SOURCES}
  ${API_SOURCES}
  ${SRC_SOURCES}
  Pbforwarder.cpp
  Ports.cpp
  Rules.cpp
  Pbforwarder-lib.cpp)

# load ebpf datapath code in std::string variables
load_file_as_variable(pcn-pbforwarder Pbforwarder_dp_parsing.c pbforwarder_code_parsing)
load_file_as_variable(pcn-pbforwarder Pbforwarder_dp_matching.c pbforwarder_code_matching)
load_file_as_variable(pcn-pbforwarder Pbforwarder_dp_action.c pbforwarder_code_action)

target_link_libraries(pcn-pbforwarder
  polycube
  uuid)

# Specify shared library install directory

set(CMAKE_INSTALL_LIBDIR /usr/lib)

install(
    TARGETS
    pcn-pbforwarder
    DESTINATION
    "${CMAKE_INSTALL_LIBDIR}"
)

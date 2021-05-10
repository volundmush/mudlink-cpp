set(header_path "${mudlink_SOURCE_DIR}/include/mudlink")

set(header "${header_path}/mudlink.hpp" "${header_path}/telnet.hpp" "${header_path}/mudconn.hpp")

set(src "mudlink.cpp" "telnet.cpp" "mudconn.cpp")

#configure_file("config.hpp.in" "${CMAKE_CURRENT_BINARY_DIR}/config_impl.hpp")

find_package(Boost REQUIRED)

add_library(mudlink ${header} ${src})
target_include_directories(mudlink PUBLIC
        $<BUILD_INTERFACE:${mudlink_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${Boost_INCLUDE_DIRS}>
        $<INSTALL_INTERFACE:${include_dest}>
        )

install(TARGETS mudlink EXPORT mudlink DESTINATION ${main_lib_dest})
install(FILES ${header} DESTINATION ${include_dest})

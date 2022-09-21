
configure_file(config.h.in "config.h" )


set(SRCS
    "RsOprf.cpp"
    "RsPsi.cpp"
    "SimpleIndex.cpp"
    )

if(VOLE_PSI_ENABLE_GMW)
    list(APPEND SRCS
        "GMW/Circuit.cpp"
        "GMW/Gmw.cpp"
        "GMW/SilentTripleGen.cpp"
    )
endif()

if(VOLE_PSI_ENABLE_CPSI)
    list(APPEND SRCS
        "RsCpsi.cpp"
    )
endif()

if(VOLE_PSI_ENABLE_OPPRF)
    list(APPEND SRCS
    "RsOpprf.cpp"
    )
endif()

add_library(volePSI STATIC ${SRCS})
target_link_libraries(volePSI oc::libOTe sparsehash libdivide)

if(APPLE)
    target_compile_options(volePSI PUBLIC
        "-std=c++${VOLE_PSI_CPP_VER}"
    )    
    target_compile_options(volePSI PRIVATE
        "-Wno-pessimizing-move"
        "-Wno-delete-non-abstract-non-virtual-dtor"
    )
elseif(MSVC)
    set_target_properties(volePSI
        PROPERTIES
            CXX_STANDARD ${VOLE_PSI_CPP_VER}
            CXX_STANDARD_REQUIRED YES
            CXX_EXTENSIONS NO
    )
else()
    target_compile_options(volePSI PUBLIC
        "-std=c++${VOLE_PSI_CPP_VER}"
    )    
endif()

if(MSVC)
    target_compile_definitions(volePSI PUBLIC "_ENABLE_EXTENDED_ALIGNED_STORAGE")
else()
    target_compile_options(volePSI PUBLIC -mavx)
endif()

#target_compile_features(volePSI PUBLIC cxx_std_17)
# make projects that include volePSI use this as an include folder
target_include_directories(volePSI PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(volePSI PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 

target_sources(vmi_shared PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/bareflank.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bareflank_events.c
)

add_subdirectory(bfsdk)

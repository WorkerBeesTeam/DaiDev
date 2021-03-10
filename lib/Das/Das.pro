QT -= gui

CONFIG += target_predeps

TARGET = Das
TEMPLATE = lib

DEFINES += DAS_LIBRARY

#QMAKE_CXXFLAGS += -save-temps

android {
    CONFIG += staticlib
}

SOURCES += \
    db/device_item_group.cpp \
    db/dig_mode.cpp \
    db/dig_mode_type.cpp \
    db/dig_param.cpp \
    db/dig_param_type.cpp \
    db/dig_status.cpp \
    db/dig_status_type.cpp \
    db/dig_type.cpp \
    db/help.cpp \
    db/scheme.cpp \
    db/scheme_group.cpp \
    db/schemed_model.cpp \
    db/sign_type.cpp \
    db/user.cpp \
    db/auth_group.cpp \
    db/dig_param_value.cpp \
    db/translation.cpp \
    db/value_view.cpp \
    device_item.cpp \
    device_item_group.cpp \
    log/log_base_item.cpp \
    log/log_event_item.cpp \
    log/log_mode_item.cpp \
    log/log_param_item.cpp \
    log/log_status_item.cpp \
    log/log_value_item.cpp \
    proto_scheme.cpp \
    scheme.cpp \
    section.cpp \
    timerange.cpp \
    param/paramgroup.cpp \
    log/log_type.cpp \
    lib.cpp \
    device.cpp \
    db/device_item_type.cpp \
    db/base_type.cpp \
    db/dig_status_category.cpp \
    db/code_item.cpp \
    db/plugin_type.cpp \
    type_managers.cpp \
    write_cache_item.cpp \
    db/device_item_value.cpp \
    db/device_item.cpp \
    db/device_extra_params.cpp \
    db/save_timer.cpp \
    checker_interface.cpp \
    db/node.cpp \
    db/disabled_param.cpp \
    db/disabled_status.cpp \
    db/chart.cpp

HEADERS +=\
    db/auth_group.h \
    db/device_item_group.h \
    db/dig_mode.h \
    db/dig_mode_type.h \
    db/dig_param.h \
    db/dig_param_type.h \
    db/dig_status.h \
    db/dig_status_type.h \
    db/dig_type.h \
    db/help.h \
    db/scheme.h \
    db/scheme_group.h \
    db/schemed_model.h \
    db/sign_type.h \
    db/user.h \
    db/dig_param_value.h \
    db/translation.h \
    db/value_view.h \
    device_item.h \
    device_item_group.h \
    log/log_base_item.h \
    log/log_event_item.h \
    log/log_mode_item.h \
    log/log_param_item.h \
    log/log_status_item.h \
    log/log_value_item.h \
    proto_scheme.h \
    scheme.h \
    section.h \
    timerange.h \
    param/paramgroup.h \
    commands.h \
    log/log_pack.h \
    log/log_type.h \
    lib.h \
    daslib_global.h \
    device.h \
    db/device_item_type.h \
    db/base_type.h \
    db/dig_status_category.h \
    db/code_item.h \
    db/plugin_type.h \
    type_managers.h \
    write_cache_item.h \
    db/device_item_value.h \
    db/device_item.h \
    db/device_extra_params.h \
    db/save_timer.h \
    checker_interface.h \
    db/node.h \
    db/disabled_param.h \
    db/disabled_status.h \
    db/chart.h

DESTDIR = $${OUT_PWD}/../..

#Target version
VER_MAJ = 1
VER_MIN = 5
include(../../common.pri)

LIBS += -lHelpzDBMeta
#LIBS += -lHelpzService -lHelpzDB -lHelpzNetwork

unix {
    target.path = /usr/local/lib
    INSTALLS += target
}

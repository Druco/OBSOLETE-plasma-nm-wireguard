add_definitions(-DTRANSLATION_DOMAIN=\"plasmanetworkmanagement_wireguardui\")

set(wireguard_SRCS
    ../../libs/debug.cpp
    wireguard.cpp
    wireguardwidget.cpp
    wireguardauth.cpp
    wireguardadvancedwidget.cpp
    wireguardutils.cpp
)

ki18n_wrap_ui(wireguard_SRCS wireguard.ui wireguardadvanced.ui)

add_library(plasmanetworkmanagement_wireguardui ${wireguard_SRCS})

kcoreaddons_desktop_to_json(plasmanetworkmanagement_wireguardui plasmanetworkmanagement_wireguardui.desktop)

target_link_libraries(plasmanetworkmanagement_wireguardui
    plasmanm_internal
    plasmanm_editor
    Qt5::Widgets
    Qt5::Network
    Qt5::DBus
    KF5::NetworkManagerQt
    KF5::Service
    KF5::Completion
    KF5::I18n
    KF5::WidgetsAddons
    KF5::KIOWidgets
    KF5::CoreAddons
    KF5::KDELibs4Support
)

install(TARGETS plasmanetworkmanagement_wireguardui  DESTINATION ${PLUGIN_INSTALL_DIR})

install(FILES plasmanetworkmanagement_wireguardui.desktop  DESTINATION ${SERVICES_INSTALL_DIR})

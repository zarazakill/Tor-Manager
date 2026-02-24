# TorManager.pro - Файл проекта для Tor Manager Server
# OpenVPN сервер с маршрутизацией трафика через Tor

QT += core gui network widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

# Использование C++17 для современных возможностей
CONFIG += c++17
CONFIG += warn_on
CONFIG += link_pkgconfig

# Отключаем устаревшие API
DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000

# Определяем архитектуру
linux-g++ | linux-g++-64 | linux-g++-32 {
    DEFINES += Q_OS_LINUX
    DEFINES += _GNU_SOURCE
}

# Версия приложения
VERSION = 1.1.0
DEFINES += APP_VERSION=\\\"$$VERSION\\\"
DEFINES += APP_NAME=\\\"TorManagerServer\\\"

# Имя исполняемого файла
TARGET = TorManager

# Заголовочные файлы
HEADERS += \
    mainwindow.h

# Исходные файлы
SOURCES += \
    main.cpp \
    mainwindow.cpp

# Ресурсы (если понадобятся)
# RESOURCES += resources.qrc

# Настройки для Linux
unix:!macx {
    # Linux специфичные настройки
    QMAKE_CXXFLAGS += -pthread
    QMAKE_CXXFLAGS += -Wno-reorder
    QMAKE_LFLAGS += -pthread

    # Подключаем библиотеки
    LIBS += -ldl -lz

    # Пути установки
    isEmpty(PREFIX) {
        PREFIX = /usr/local
    }

    target.path = $$PREFIX/bin

    # Создание desktop файла
    desktop.path = $$PREFIX/share/applications
    desktop.files += TorManager.desktop

    # Иконка
    icon.path = $$PREFIX/share/icons/hicolor/256x256/apps
    icon.files += TorManager.png

    INSTALLS += target desktop icon
}

# Для отладочной сборки
CONFIG(debug, debug|release) {
    DEFINES += DEBUG_MODE
    TARGET = $$join(TARGET,,,d)
    message("Debug build")
}

# Для релизной сборки
CONFIG(release, debug|release) {
    DEFINES += QT_NO_DEBUG_OUTPUT
    DEFINES += QT_NO_WARNING_OUTPUT
    message("Release build")
}

# Статическая линковка (опционально)
# CONFIG += static
# QMAKE_LFLAGS += -static

# Проверка наличия OpenSSL
packagesExist(openssl) {
    PKGCONFIG += openssl
    DEFINES += HAVE_OPENSSL
    message("OpenSSL found")
} else {
    warning("OpenSSL not found, certificate generation may be limited")
}

# Дополнительные флаги для безопасности
QMAKE_CXXFLAGS += -fstack-protector-strong
QMAKE_CXXFLAGS += -D_FORTIFY_SOURCE=2
QMAKE_LFLAGS += -Wl,-z,relro,-z,now

# Информация о сборке
BUILD_DATE = $$system(date +%Y%m%d)
DEFINES += BUILD_DATE=\\\"$$BUILD_DATE\\\"

# Компиляция с оптимизацией
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3
QMAKE_CXXFLAGS_RELEASE += -march=x86-64 -mtune=generic

# Дебаг символы в релизе
QMAKE_CXXFLAGS_RELEASE += -g

# Создание файла с информацией о версии
version.target = version.h
version.commands = echo \#define GIT_VERSION \\\"$$system(git describe --tags --always 2>/dev/null || echo unknown)\\\" > version.h
version.depends =
QMAKE_EXTRA_TARGETS += version
PRE_TARGETDEPS += version.h

# Очистка
QMAKE_CLEAN += version.h

# Установка разрешений для исполняемого файла
unix:!macx {
    QMAKE_POST_LINK += chmod 755 $(TARGET) ;
}

# ========== ПРОВЕРКА НАЛИЧИЯ ЗАВИСИМОСТЕЙ ==========

# Проверка на наличие EasyRSA для генерации сертификатов
exists(/usr/share/easy-rsa/easyrsa) {
    DEFINES += HAVE_EASYRSA
    message("EasyRSA found - certificate generation will be available")
} else {
    exists(/usr/local/share/easy-rsa/easyrsa) {
        DEFINES += HAVE_EASYRSA
        message("EasyRSA found in /usr/local - certificate generation will be available")
    } else {
        warning("EasyRSA not found - will use OpenSSL for certificate generation")
    }
}

# Проверка на наличие Tor
exists(/usr/bin/tor) {
    DEFINES += HAVE_TOR
    message("Tor found")
} else {
    exists(/usr/local/bin/tor) {
        DEFINES += HAVE_TOR
        message("Tor found in /usr/local")
    } else {
        warning("Tor not found in standard paths")
    }
}

# Проверка на наличие OpenVPN
exists(/usr/sbin/openvpn) {
    DEFINES += HAVE_OPENVPN
    message("OpenVPN found")
} else {
    exists(/usr/bin/openvpn) {
        DEFINES += HAVE_OPENVPN
        message("OpenVPN found in /usr/bin")
    } else {
        exists(/usr/local/sbin/openvpn) {
            DEFINES += HAVE_OPENVPN
            message("OpenVPN found in /usr/local")
        } else {
            warning("OpenVPN not found in standard paths")
        }
    }
}

# ========== ПРОВЕРКА НАЛИЧИЯ ТРАНСПОРТНЫХ ПЛАГИНОВ ==========

# Проверка на наличие lyrebird (универсальный плагин)
exists(/usr/bin/lyrebird) {
    DEFINES += HAVE_LYREBIRD
    message("Lyrebird found - unified pluggable transport")
} else {
    exists(/usr/local/bin/lyrebird) {
        DEFINES += HAVE_LYREBIRD
        message("Lyrebird found in /usr/local")
    }
}

# Проверка на наличие obfs4proxy
exists(/usr/bin/obfs4proxy) {
    DEFINES += HAVE_OBFS4
    message("obfs4proxy found")
} else {
    exists(/usr/local/bin/obfs4proxy) {
        DEFINES += HAVE_OBFS4
        message("obfs4proxy found in /usr/local")
    }
}

# Проверка на наличие webtunnel
exists(/usr/bin/webtunnel) {
    DEFINES += HAVE_WEBTUNNEL
    message("WebTunnel found")
} else {
    exists(/usr/local/bin/webtunnel) {
        DEFINES += HAVE_WEBTUNNEL
        message("WebTunnel found in /usr/local")
    }
}

# Проверка на наличие snowflake-client
exists(/usr/bin/snowflake-client) {
    DEFINES += HAVE_SNOWFLAKE
    message("Snowflake client found")
} else {
    exists(/usr/local/bin/snowflake-client) {
        DEFINES += HAVE_SNOWFLAKE
        message("Snowflake client found in /usr/local")
    }
}

# ========== СОЗДАНИЕ НЕОБХОДИМЫХ ДИРЕКТОРИЙ ==========

# Создание директорий для конфигурации при установке
unix:!macx {
    system(mkdir -p /etc/TorManager 2>/dev/null || true)
    system(mkdir -p /var/log/TorManager 2>/dev/null || true)
    system(chmod 755 /etc/TorManager 2>/dev/null || true)
    system(chmod 755 /var/log/TorManager 2>/dev/null || true)
    system(mkdir -p /var/lib/TorManager/certs 2>/dev/null || true)
    system(chmod 755 /var/lib/TorManager 2>/dev/null || true)

    message("Created directories: /etc/TorManager, /var/log/TorManager, /var/lib/TorManager/certs")
}

# ========== ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ ==========

# Включаем поддержку IPv6
DEFINES += QT_NETWORK_ALLOW_IPV6

# Максимальный размер лога
DEFINES += MAX_LOG_LINES=10000

# Таймауты
DEFINES += BRIDGE_TEST_TIMEOUT=5000
DEFINES += CLIENT_STATS_UPDATE_INTERVAL=5000
DEFINES += CLIENTS_REFRESH_INTERVAL=3000  # Обновление таблицы клиентов каждые 3 сек

# Путь к конфигурации по умолчанию
DEFINES += DEFAULT_CONFIG_PATH=\\\"/etc/TorManager\\\"

# Версия с поддержкой вкладки клиентов
DEFINES += FEATURE_CLIENTS_TAB=1

# Вывод информации о сборке
message("========================================")
message("Tor Manager Server Build Configuration")
message("========================================")
message("Qt version: $$QT_VERSION")
message("Build type: $$CONFIG")
message("Installation prefix: $$PREFIX")
message("C++ standard: C++17")
message("Features: Tor, OpenVPN Server, Client Management Tab")
message("========================================")

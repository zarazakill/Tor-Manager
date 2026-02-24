#include "mainwindow.h"
#include <QApplication>
#include <QMessageBox>
#include <QStyleFactory>
#include <QTranslator>
#include <QLocale>
#include <QSettings>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QDebug>
#include <QTimer>
#include <QLibraryInfo>

#ifdef Q_OS_LINUX
#include <unistd.h>
#include <sys/types.h>
#include <csignal>
#endif

/**
 * Главная функция приложения Tor Manager (Серверная версия)
 */
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    // Настройка организации и приложения
    QCoreApplication::setOrganizationName("TorManager");
    QCoreApplication::setOrganizationDomain("tormanager.local");
    QCoreApplication::setApplicationName("TorManager-Server");
    QCoreApplication::setApplicationVersion("1.0.0");

    // Установка локали
    QLocale::setDefault(QLocale(QLocale::Russian, QLocale::RussianFederation));

    // Установка стиля
    app.setStyle(QStyleFactory::create("Fusion"));

    // Настройка русского перевода для Qt
    QTranslator qtTranslator;
    QString translationsPath = QLibraryInfo::path(QLibraryInfo::TranslationsPath);
    if (qtTranslator.load(QLocale(), "qt", "_", translationsPath)) {
        app.installTranslator(&qtTranslator);
    }

    // Создаем необходимые директории
    QString appDataPath = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    QDir appDir(appDataPath);
    if (!appDir.exists()) {
        appDir.mkpath(".");
    }

    QString torDataDir = appDataPath + "/tor_data";
    QDir torDir(torDataDir);
    if (!torDir.exists()) {
        torDir.mkpath(".");
        qDebug() << "Создана директория для данных Tor:" << torDataDir;
    }

    QString certsDir = appDataPath + "/certs";
    QDir certs(certsDir);
    if (!certs.exists()) {
        certs.mkpath(".");
        qDebug() << "Создана директория для сертификатов:" << certsDir;
    }

    // Проверка прав доступа (только для Linux)
    #ifdef Q_OS_LINUX
    uid_t uid = geteuid();
    if (uid != 0) {
        qDebug() << "Приложение запущено без root-прав. UID:" << uid;

        QSettings settings("TorManager", "TorVPN");
        bool suppressWarning = settings.value("security/suppressPrivilegeWarning", false).toBool();

        if (!suppressWarning) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Предупреждение о привилегиях");
            msgBox.setText(
                "<h3>Требуются права root</h3>"
                "<p>Для управления VPN сервером и настройки файрвола (kill switch) "
                "требуются права суперпользователя.</p>"
                "<p><b>Возможные варианты:</b></p>"
                "<ul>"
                "<li>Запустите с sudo: <code>sudo ./TorManager</code></li>"
                "<li>Настройте polkit для OpenVPN</li>"
                "<li>Используйте pkexec</li>"
                "</ul>"
                "<p><b>Функции, которые не будут работать без root-прав:</b></p>"
                "<ul>"
                "<li>Запуск OpenVPN сервера</li>"
                "<li>Kill switch (блокировка трафика)</li>"
                "<li>Настройка файрвола</li>"
                "<li>Маршрутизация клиентов через Tor</li>"
                "</ul>"
                "<p>Tor будет работать в обычном режиме.</p>"
            );
            msgBox.setIcon(QMessageBox::Warning);
            msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No | QMessageBox::Ignore);
            msgBox.button(QMessageBox::Yes)->setText("Продолжить");
            msgBox.button(QMessageBox::No)->setText("Выйти");
            msgBox.button(QMessageBox::Ignore)->setText("Больше не показывать");

            int ret = msgBox.exec();

            if (ret == QMessageBox::No) {
                return 0;
            } else if (ret == QMessageBox::Ignore) {
                settings.setValue("security/suppressPrivilegeWarning", true);
                settings.sync();
            }
        }
    } else {
        qDebug() << "Приложение запущено с root-правами. Все функции доступны.";
    }
    #endif

    // Проверка наличия Tor
    QStringList torPaths = {
        "/usr/bin/tor",
        "/usr/local/bin/tor",
        "/usr/sbin/tor",
        "/snap/bin/tor"
    };

    for (const QString &path : torPaths) {
        if (QFile::exists(path)) {
            qDebug() << "Найден Tor:" << path;
            break;
        }
    }

    // Проверка наличия OpenVPN
    QStringList openVPNPaths = {
        "/usr/sbin/openvpn",
        "/usr/bin/openvpn",
        "/usr/local/sbin/openvpn",
        "/snap/bin/openvpn"
    };

    for (const QString &path : openVPNPaths) {
        if (QFile::exists(path)) {
            qDebug() << "Найден OpenVPN:" << path;
            break;
        }
    }

    // Создаем главное окно
    MainWindow window;

    // Загружаем настройки окна
    QSettings settings("TorManager", "TorVPN");

    if (settings.contains("window/geometry")) {
        window.restoreGeometry(settings.value("window/geometry").toByteArray());
    }

    if (settings.contains("window/state")) {
        window.restoreState(settings.value("window/state").toByteArray());
    }

    bool startMinimized = settings.value("general/startMinimized", false).toBool();
    bool torWasRunning = settings.value("tor/wasRunning", false).toBool();
    bool serverWasRunning = settings.value("server/wasRunning", false).toBool();

    if (startMinimized) {
        qDebug() << "Запуск в свернутом режиме";
        window.hide();

        if (torWasRunning) {
            qDebug() << "Автоматический запуск Tor (был запущен ранее)";
            QTimer::singleShot(2000, &window, &MainWindow::startTor);
        }

        if (serverWasRunning) {
            qDebug() << "Автоматический запуск VPN сервера (был запущен ранее)";
            QTimer::singleShot(5000, &window, [&window]() {
                window.startOpenVPNServer();
            });
        }

        if (window.trayIcon && window.trayIcon->isVisible()) {
            window.trayIcon->showMessage(
                "Tor Manager Server",
                "Приложение запущено в фоновом режиме. Дважды щелкните по иконке в трее для открытия.",
                QSystemTrayIcon::Information,
                3000
            );
        }
    } else {
        qDebug() << "Запуск в нормальном режиме";
        window.show();

        if (torWasRunning) {
            QTimer::singleShot(500, [&window]() {
                QMessageBox::StandardButton reply = QMessageBox::question(
                    &window,
                    "Автозапуск Tor",
                    "Tor был запущен при прошлом закрытии программы. Запустить Tor сейчас?",
                    QMessageBox::Yes | QMessageBox::No
                );

                if (reply == QMessageBox::Yes) {
                    window.startTor();
                }
            });
        }

        if (serverWasRunning) {
            QTimer::singleShot(1000, [&window]() {
                QMessageBox::StandardButton reply = QMessageBox::question(
                    &window,
                    "Автозапуск VPN сервера",
                    "VPN сервер был запущен при прошлом закрытии программы. Запустить сервер сейчас?",
                    QMessageBox::Yes | QMessageBox::No
                );

                if (reply == QMessageBox::Yes) {
                    window.startOpenVPNServer();
                }
            });
        }
    }

    // Обработка аргументов командной строки
    QStringList args = app.arguments();
    if (args.contains("--help") || args.contains("-h")) {
        QMessageBox::information(nullptr, "Справка Tor Manager Server",
                                 "<h3>Использование:</h3>"
                                 "<p>TorManager [опции]</p>"
                                 "<h4>Опции:</h4>"
                                 "<ul>"
                                 "<li><b>--help, -h</b> - показать эту справку</li>"
                                 "<li><b>--minimized</b> - запустить свернутым</li>"
                                 "<li><b>--start-tor</b> - автоматически запустить Tor</li>"
                                 "<li><b>--start-server</b> - автоматически запустить VPN сервер</li>"
                                 "<li><b>--quiet</b> - не показывать предупреждения</li>"
                                 "</ul>"
        );
        return 0;
    }

    if (args.contains("--minimized") && !startMinimized) {
        window.hide();
    }

    if (args.contains("--start-tor")) {
        QTimer::singleShot(1000, &window, &MainWindow::startTor);
    }

    if (args.contains("--start-server")) {
        QTimer::singleShot(2000, &window, &MainWindow::startOpenVPNServer);
    }

    // Обработка сигналов для корректного завершения (только для Linux)
    #ifdef Q_OS_LINUX
    struct sigaction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = [](int) {
        qDebug() << "Получен сигнал, завершение работы...";
        QApplication::quit();
    };

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    #endif

    qDebug() << "Приложение запущено. Версия:" << QCoreApplication::applicationVersion();

    int result = app.exec();

    // Сохраняем состояние перед выходом
    settings.setValue("tor/wasRunning", window.torRunning);
    settings.setValue("server/wasRunning", window.serverMode);
    settings.setValue("window/geometry", window.saveGeometry());
    settings.setValue("window/state", window.saveState());
    settings.sync();

    qDebug() << "Приложение завершается с кодом:" << result;

    return result;
}

#include "mainwindow.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QDir>
#include <QStandardPaths>
#include <QCloseEvent>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QSplitter>
#include <QMenuBar>
#include <QStatusBar>
#include <QInputDialog>
#include <QNetworkProxy>
#include <QClipboard>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QScrollArea>
#include <QDesktopServices>
#include <QApplication>
#include <QHeaderView>
#include <QMenu>
#include <csignal>
#include <QGuiApplication>

#ifdef Q_OS_LINUX
#include <unistd.h>
#include <sys/types.h>
#endif

// Определения статических констант
const int MainWindow::DEFAULT_TOR_SOCKS_PORT = 9050;
const int MainWindow::DEFAULT_TOR_CONTROL_PORT = 9051;
const int MainWindow::DEFAULT_VPN_SERVER_PORT = 1194;
const int MainWindow::MAX_LOG_LINES = 10000;
const int MainWindow::BRIDGE_TEST_TIMEOUT = 5000;
const int MainWindow::CLIENT_STATS_UPDATE_INTERVAL = 5000;

// ========== РЕАЛИЗАЦИЯ CERTIFICATEGENERATOR ==========

CertificateGenerator::CertificateGenerator(QObject *parent)
: QObject(parent)
, currentProcess(nullptr)
, currentCommandIndex(0)
, useEasyRSAFlag(false)
{
    currentProcess = new QProcess(this);

    connect(currentProcess, &QProcess::finished,
            this, &CertificateGenerator::onProcessFinished);
    connect(currentProcess, &QProcess::errorOccurred,
            this, &CertificateGenerator::onProcessError);
    connect(currentProcess, &QProcess::readyReadStandardOutput,
            this, &CertificateGenerator::onProcessOutput);
    connect(currentProcess, &QProcess::readyReadStandardError,
            this, &CertificateGenerator::onProcessErrorOutput);
}

void CertificateGenerator::generateCertificates(const QString &certsDir,
                                                const QString &openVPNPath,
                                                bool useEasyRSA)
{
    this->certsDirectory = certsDir;
    this->openVPNPath = openVPNPath;
    this->useEasyRSAFlag = useEasyRSA;
    this->commandQueue.clear();
    this->currentCommandIndex = 0;

    QDir().mkpath(certsDir);

    emit logMessage("Начало генерации сертификатов...", "info");
    emit progress(0);

    if (useEasyRSAFlag) {
        commandQueue << "init-pki"
        << "build-ca nopass"
        << "build-server-full server nopass"
        << "gen-dh";
    } else {
        commandQueue << "genrsa_ca"
        << "req_ca"
        << "genrsa_server"
        << "req_server"
        << "sign_server"
        << "dhparam"
        << "tlsauth";
    }

    runNextCommand();
}

void CertificateGenerator::runNextCommand()
{
    if (currentCommandIndex >= commandQueue.size()) {
        // Копируем файлы в целевую директорию
        if (useEasyRSAFlag) {
            QString workDir = certsDirectory + "/easy-rsa/pki";
            QFile::copy(workDir + "/ca.crt", certsDirectory + "/ca.crt");
            QFile::copy(workDir + "/issued/server.crt", certsDirectory + "/server.crt");
            QFile::copy(workDir + "/private/server.key", certsDirectory + "/server.key");
            QFile::copy(workDir + "/dh.pem", certsDirectory + "/dh.pem");
        }

        emit finished(true);
        return;
    }

    QString cmd = commandQueue[currentCommandIndex];
    emit progress((currentCommandIndex * 100) / commandQueue.size());

    if (useEasyRSAFlag) {
        runEasyRSACommand(cmd, cmd);
    } else {
        if (cmd == "genrsa_ca") {
            runOpenSSLCommand({"genrsa", "-out", certsDirectory + "/ca.key", "2048"},
                              "Генерация CA ключа");
        } else if (cmd == "req_ca") {
            runOpenSSLCommand({"req", "-new", "-x509", "-days", "3650",
                "-key", certsDirectory + "/ca.key",
                "-out", certsDirectory + "/ca.crt",
                "-subj", "/C=RU/ST=Moscow/L=Moscow/O=TorManager/CN=TorManager CA"},
                "Генерация CA сертификата");
        } else if (cmd == "genrsa_server") {
            runOpenSSLCommand({"genrsa", "-out", certsDirectory + "/server.key", "2048"},
                              "Генерация ключа сервера");
        } else if (cmd == "req_server") {
            runOpenSSLCommand({"req", "-new",
                "-key", certsDirectory + "/server.key",
                "-out", certsDirectory + "/server.csr",
                "-subj", "/C=RU/ST=Moscow/L=Moscow/O=TorManager/CN=server"},
                "Генерация CSR сервера");
        } else if (cmd == "sign_server") {
            runOpenSSLCommand({"x509", "-req",
                "-in", certsDirectory + "/server.csr",
                "-CA", certsDirectory + "/ca.crt",
                "-CAkey", certsDirectory + "/ca.key",
                "-CAcreateserial",
                "-out", certsDirectory + "/server.crt",
                "-days", "365"},
                "Подпись сертификата сервера");
        } else if (cmd == "dhparam") {
            emit logMessage("Генерация DH параметров (может занять несколько минут)...", "info");
            runOpenSSLCommand({"dhparam", "-out", certsDirectory + "/dh.pem", "2048"},
                              "Генерация DH параметров");
        } else if (cmd == "tlsauth") {
            QString openvpn = openVPNPath.isEmpty() ? "/usr/sbin/openvpn" : openVPNPath;
            QProcess *taProcess = new QProcess(this);
            connect(taProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                    [this, taProcess](int code, QProcess::ExitStatus) {
                        if (code == 0) {
                            emit logMessage("TLS-Auth ключ сгенерирован", "success");
                        } else {
                            emit logMessage("Ошибка генерации TLS-Auth ключа", "error");
                        }
                        taProcess->deleteLater();
                        currentCommandIndex++;
                        runNextCommand();
                    });
            taProcess->start(openvpn, {"--genkey", "--secret", certsDirectory + "/ta.key"});
            return;
        }
    }
}

void CertificateGenerator::runOpenSSLCommand(const QStringList &args, const QString &description)
{
    emit logMessage("Выполняется: " + description, "info");

    currentProcess->setProgram("openssl");
    currentProcess->setArguments(args);
    currentProcess->setWorkingDirectory(certsDirectory);
    currentProcess->start();
}

void CertificateGenerator::runEasyRSACommand(const QString &cmd, const QString &description)
{
    emit logMessage("Выполняется EasyRSA: " + description, "info");

    QString easyRSAPath = "/usr/share/easy-rsa/easyrsa";

    QStringList args;
    if (cmd == "init-pki") {
        args << "init-pki";
    } else if (cmd == "build-ca nopass") {
        args << "build-ca" << "nopass";
    } else if (cmd == "build-server-full server nopass") {
        args << "build-server-full" << "server" << "nopass";
    } else if (cmd == "gen-dh") {
        args << "gen-dh";
    }

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("EASYRSA_BATCH", "1");
    env.insert("EASYRSA_REQ_CN", "TorManager");
    env.insert("EASYRSA_REQ_ORG", "TorManager");

    currentProcess->setProgram(easyRSAPath);
    currentProcess->setArguments(args);
    currentProcess->setProcessEnvironment(env);
    currentProcess->setWorkingDirectory(certsDirectory + "/easy-rsa");

    QDir().mkpath(certsDirectory + "/easy-rsa");
    currentProcess->start();
}

void CertificateGenerator::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (exitStatus == QProcess::NormalExit && exitCode == 0) {
        emit logMessage("Команда выполнена успешно", "success");
        currentCommandIndex++;
        runNextCommand();
    } else {
        emit logMessage(QString("Ошибка выполнения команды (код %1)").arg(exitCode), "error");
        emit finished(false);
    }
}

void CertificateGenerator::onProcessError(QProcess::ProcessError error)
{
    QString errorStr;
    switch (error) {
        case QProcess::FailedToStart:
            errorStr = "Не удалось запустить процесс";
            break;
        case QProcess::Crashed:
            errorStr = "Процесс аварийно завершился";
            break;
        case QProcess::Timedout:
            errorStr = "Таймаут процесса";
            break;
        default:
            errorStr = "Неизвестная ошибка";
    }

    emit logMessage("Ошибка: " + errorStr, "error");
    emit finished(false);
}

void CertificateGenerator::onProcessOutput()
{
    QString output = QString::fromUtf8(currentProcess->readAllStandardOutput());
    if (!output.isEmpty()) {
        emit logMessage(output.trimmed(), "info");
    }
}

void CertificateGenerator::onProcessErrorOutput()
{
    QString error = QString::fromUtf8(currentProcess->readAllStandardError());
    if (!error.isEmpty()) {
        if (!error.contains("warning") && !error.contains("deprecated")) {
            emit logMessage("stderr: " + error.trimmed(), "warning");
        }
    }
}

// ========== РЕАЛИЗАЦИЯ MAINWINDOW ==========

MainWindow::MainWindow(QWidget *parent)
: QMainWindow(parent)
, tabWidget(nullptr)
, torTab(nullptr)
, btnStartTor(nullptr)
, btnStopTor(nullptr)
, btnRestartTor(nullptr)
, btnNewCircuit(nullptr)
, lblTorStatus(nullptr)
, lblTorIP(nullptr)
, lblCircuitInfo(nullptr)
, txtTorLog(nullptr)
, cboBridgeType(nullptr)
, lstBridges(nullptr)
, btnAddBridge(nullptr)
, btnRemoveBridge(nullptr)
, lblTrafficStats(nullptr)
, btnImportBridges(nullptr)
, btnTestBridge(nullptr)
, lblBridgeStats(nullptr)
, serverTab(nullptr)
, serverGroup(nullptr)
, spinServerPort(nullptr)
, txtServerNetwork(nullptr)
, chkRouteThroughTor(nullptr)
, btnGenerateCerts(nullptr)
, btnCheckCerts(nullptr)
, btnStartServer(nullptr)
, btnStopServer(nullptr)
, lblServerStatus(nullptr)
, lblConnectedClients(nullptr)
, txtServerLog(nullptr)
, lblCurrentIP(nullptr)
, btnCheckIP(nullptr)
, btnGenerateClientConfig(nullptr)
, btnDiagnose(nullptr)
, btnTestConfig(nullptr)
, clientsTab(nullptr)
, clientsTable(nullptr)
, txtClientsLog(nullptr)
, btnDisconnectClient(nullptr)
, btnDisconnectAll(nullptr)
, btnRefreshClients(nullptr)
, btnClientDetails(nullptr)
, btnBanClient(nullptr)
, btnExportClientsLog(nullptr)
, btnClearClientsLog(nullptr)
, lblTotalClients(nullptr)
, lblActiveClients(nullptr)
, clientsRefreshTimer(nullptr)
, settingsTab(nullptr)
, spinTorSocksPort(nullptr)
, spinTorControlPort(nullptr)
, chkAutoStart(nullptr)
, chkKillSwitch(nullptr)
, chkBlockIPv6(nullptr)
, chkDNSLeakProtection(nullptr)
, chkStartMinimized(nullptr)
, txtTorPath(nullptr)
, txtOpenVPNPath(nullptr)
, btnApplySettings(nullptr)
, btnBrowseTor(nullptr)
, btnBrowseOpenVPN(nullptr)
, logsTab(nullptr)
, txtAllLogs(nullptr)
, cboLogLevel(nullptr)
, btnClearLogs(nullptr)
, btnSaveLogs(nullptr)
, trayMenu(nullptr)
, torProcess(nullptr)
, openVPNServerProcess(nullptr)
, certGenerator(nullptr)
, controlSocket(nullptr)
, ipCheckManager(nullptr)
, statusTimer(nullptr)
, trafficTimer(nullptr)
, clientStatsTimer(nullptr)
, settings(nullptr)
, killSwitchEnabled(false)
, controlSocketConnected(false)
, serverStopPending(false)
, serverTorWaitRetries(0)
, currentConnectionState("disconnected")
, currentIP()
, torIP()
, bytesReceived(0)
, bytesSent(0)
, connectedClients(0)
, tempLinkPath()
, torrcPath()
, torDataDir()
, serverConfigPath()
, torExecutablePath()
, openVPNExecutablePath()
, certsDir()
, caCertPath()
, serverCertPath()
, serverKeyPath()
, dhParamPath()
, taKeyPath()
, configuredBridges()
, transportPluginPaths()
{
    // Инициализация компонентов
    settings = new QSettings("TorManager", "TorVPN", this);
    torProcess = new QProcess(this);
    openVPNServerProcess = new QProcess(this);
    openVPNServerProcess->setProcessChannelMode(QProcess::MergedChannels);
    controlSocket = new QTcpSocket(this);
    ipCheckManager = new QNetworkAccessManager(this);

    statusTimer = new QTimer(this);
    trafficTimer = new QTimer(this);
    clientStatsTimer = new QTimer(this);
    clientsRefreshTimer = new QTimer(this);

    // Настройка путей
    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(appData);
    torDataDir = appData + "/tor_data";
    torrcPath = appData + "/torrc";
    serverConfigPath = appData + "/server.conf";
    QDir().mkpath(torDataDir);

    // Пути для сертификатов
    certsDir = appData + "/certs";
    QDir().mkpath(certsDir);
    caCertPath = certsDir + "/ca.crt";
    serverCertPath = certsDir + "/server.crt";
    serverKeyPath = certsDir + "/server.key";
    dhParamPath = certsDir + "/dh.pem";
    taKeyPath = certsDir + "/ta.key";

    // Создаём UI
    setupUI();

    // Загружаем настройки
    loadSettings();

    // Проверка наличия Tor и OpenVPN
    if (!checkTorInstalled()) {
        addLogMessage("Предупреждение: Tor не найден. Укажите путь в настройках.", "warning");
    }

    if (!checkOpenVPNInstalled()) {
        addLogMessage("Предупреждение: OpenVPN не найден. Укажите путь в настройках.", "warning");
    }

    setupTrayIcon();
    setupConnections();
    createTorConfig();
    loadBridgesFromSettings();

    // Загружаем историю логов клиентов
    loadClientsLogHistory();

    // Запуск таймеров
    statusTimer->start(5000);
    trafficTimer->start(2000);
    clientStatsTimer->start(CLIENT_STATS_UPDATE_INTERVAL);
    clientsRefreshTimer->start(3000);  // Обновление таблицы клиентов каждые 3 сек

    // Автозапуск если включен
    if (settings->value("autoStart", false).toBool()) {
        QTimer::singleShot(1000, this, &MainWindow::startTor);
    }

    setWindowTitle("Tor Manager с OpenVPN (Сервер)");
    resize(1000, 750);  // Увеличили размер окна для новой вкладки

    addLogMessage("Tor Manager успешно инициализирован", "info");
}

MainWindow::~MainWindow()
{
    stopOpenVPNServer();
    stopTor();

    if (killSwitchEnabled) {
        disableKillSwitch();
    }

    // Очистка временных ссылок
    if (!tempLinkPath.isEmpty()) {
        QDir(tempLinkPath).removeRecursively();
    }

    // Очистка оберток скриптов
    QFile::remove("/tmp/tormgr_scripts/up_wrapper.sh");
    QFile::remove("/tmp/tormgr_scripts/down_wrapper.sh");
    QDir("/tmp/tormgr_scripts").rmdir("/tmp/tormgr_scripts");

    saveSettings();
    saveBridgesToSettings();
}

// ========== НАСТРОЙКА ИНТЕРФЕЙСА ==========

void MainWindow::setupUI()
{
    createMenuBar();
    createTabWidget();
    setCentralWidget(tabWidget);
    statusBar()->showMessage("Готов");
}

void MainWindow::createMenuBar()
{
    QMenuBar *menuBar = new QMenuBar(this);

    QMenu *fileMenu = menuBar->addMenu("&Файл");
    fileMenu->addAction("&Настройки", this, &MainWindow::showSettings);
    fileMenu->addSeparator();
    fileMenu->addAction("&Выход", this, &QWidget::close);

    QMenu *connMenu = menuBar->addMenu("&Подключение");
    connMenu->addAction("Запустить &Tor", this, &MainWindow::startTor);
    connMenu->addAction("Остановить T&or", this, &MainWindow::stopTor);
    connMenu->addAction("&Перезапустить Tor", this, &MainWindow::restartTor);
    connMenu->addSeparator();
    connMenu->addAction("Запустить VPN &сервер", this, &MainWindow::startOpenVPNServer);
    connMenu->addAction("Остановить VPN се&рвер", this, &MainWindow::stopOpenVPNServer);
    connMenu->addSeparator();
    connMenu->addAction("&Новая цепочка", this, &MainWindow::requestNewCircuit);

    QMenu *toolsMenu = menuBar->addMenu("&Инструменты");
    toolsMenu->addAction("Проверить &IP-адрес", this, &MainWindow::checkIPLeak);
    toolsMenu->addSeparator();
    toolsMenu->addAction("Включить Kill Switch", this, &MainWindow::enableKillSwitch);
    toolsMenu->addAction("Отключить Kill Switch", this, &MainWindow::disableKillSwitch);
    toolsMenu->addSeparator();
    toolsMenu->addAction("Сгенерировать сертификаты", this, &MainWindow::generateCertificates);
    toolsMenu->addAction("Проверить сертификаты", this, &MainWindow::checkCertificates);
    toolsMenu->addSeparator();
    toolsMenu->addAction("Диагностика сервера", this, &MainWindow::diagnoseConnection);
    toolsMenu->addAction("Проверить конфигурацию", this, &MainWindow::testServerConfig);
    toolsMenu->addAction("Проверить маршрутизацию", this, &MainWindow::verifyRouting);
    toolsMenu->addSeparator();
    toolsMenu->addAction("История логов клиентов", this, &MainWindow::showFullClientsLog);

    QMenu *helpMenu = menuBar->addMenu("&Помощь");
    helpMenu->addAction("&О программе", this, &MainWindow::showAbout);

    setMenuBar(menuBar);
}

void MainWindow::createTabWidget()
{
    tabWidget = new QTabWidget(this);

    createTorTab();
    createServerTab();
    createClientsTab();
    createSettingsTab();
    createLogsTab();

    tabWidget->addTab(torTab, "Управление Tor");
    tabWidget->addTab(serverTab, "VPN Сервер");
    tabWidget->addTab(clientsTab, "Клиенты");
    tabWidget->addTab(settingsTab, "Настройки");
    tabWidget->addTab(logsTab, "Журналы");
}

void MainWindow::createTorTab()
{
    torTab = new QWidget();
    QVBoxLayout *mainLayout = new QVBoxLayout(torTab);

    // Группа статуса
    QGroupBox *statusGroup = new QGroupBox("Статус Tor");
    QVBoxLayout *statusLayout = new QVBoxLayout(statusGroup);

    lblTorStatus = new QLabel("Статус: <b style='color:red;'>Отключен</b>");
    lblTorIP = new QLabel("IP: Неизвестно");
    lblCircuitInfo = new QLabel("Цепочка: Н/Д");
    lblTrafficStats = new QLabel("Трафик: ↓ 0 Б ↑ 0 Б");

    statusLayout->addWidget(lblTorStatus);
    statusLayout->addWidget(lblTorIP);
    statusLayout->addWidget(lblCircuitInfo);
    statusLayout->addWidget(lblTrafficStats);

    mainLayout->addWidget(statusGroup);

    // Кнопки управления
    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnStartTor = new QPushButton("Запустить Tor");
    btnStopTor = new QPushButton("Остановить Tor");
    btnRestartTor = new QPushButton("Перезапустить");
    btnNewCircuit = new QPushButton("Новая цепочка");

    btnStopTor->setEnabled(false);
    btnNewCircuit->setEnabled(false);

    btnLayout->addWidget(btnStartTor);
    btnLayout->addWidget(btnStopTor);
    btnLayout->addWidget(btnRestartTor);
    btnLayout->addWidget(btnNewCircuit);
    btnLayout->addStretch();

    mainLayout->addLayout(btnLayout);

    // Группа конфигурации мостов
    QGroupBox *bridgeGroup = new QGroupBox("Конфигурация мостов");
    QVBoxLayout *bridgeLayout = new QVBoxLayout(bridgeGroup);

    QHBoxLayout *bridgeControlLayout = new QHBoxLayout();

    cboBridgeType = new QComboBox();
    cboBridgeType->addItems({"Нет", "obfs4 (lyrebird)", "webtunnel", "snowflake", "Автоопределение"});

    btnAddBridge = new QPushButton("Добавить мост");
    btnRemoveBridge = new QPushButton("Удалить");
    btnImportBridges = new QPushButton("Импорт списка");
    btnTestBridge = new QPushButton("Проверить");

    bridgeControlLayout->addWidget(new QLabel("Тип:"));
    bridgeControlLayout->addWidget(cboBridgeType);
    bridgeControlLayout->addWidget(btnAddBridge);
    bridgeControlLayout->addWidget(btnRemoveBridge);
    bridgeControlLayout->addWidget(btnImportBridges);
    bridgeControlLayout->addWidget(btnTestBridge);

    lblBridgeStats = new QLabel("Мосты: 0 настроено");
    lblBridgeStats->setStyleSheet("color: gray; font-size: 10px;");

    lstBridges = new QListWidget();
    lstBridges->setSelectionMode(QAbstractItemView::ExtendedSelection);
    lstBridges->setContextMenuPolicy(Qt::CustomContextMenu);

    QLabel *bridgeHint = new QLabel(
        "<span style='color: gray; font-size: 9px;'>"
        "Поддерживаемые форматы:<br>"
        "• obfs4: obfs4 IP:ПОРТ ОТПЕЧАТОК cert=... iat-mode=...<br>"
        "• webtunnel: webtunnel [IPv6]:ПОРТ ОТПЕЧАТОК url=... ver=...<br>"
        "• Можно вставлять несколько строк сразу"
        "</span>"
    );
    bridgeHint->setWordWrap(true);
    bridgeHint->setTextFormat(Qt::RichText);

    bridgeLayout->addLayout(bridgeControlLayout);
    bridgeLayout->addWidget(lblBridgeStats);
    bridgeLayout->addWidget(lstBridges);
    bridgeLayout->addWidget(bridgeHint);

    mainLayout->addWidget(bridgeGroup);

    // Журнал Tor
    QGroupBox *logGroup = new QGroupBox("Журнал Tor");
    QVBoxLayout *logLayout = new QVBoxLayout(logGroup);

    txtTorLog = new QTextEdit();
    txtTorLog->setReadOnly(true);
    txtTorLog->setMaximumHeight(200);
    logLayout->addWidget(txtTorLog);

    mainLayout->addWidget(logGroup);
}

void MainWindow::createServerTab()
{
    serverTab = new QWidget();
    QVBoxLayout *mainLayout = new QVBoxLayout(serverTab);

    // Группа сервера
    serverGroup = new QGroupBox("Управление OpenVPN сервером");
    QVBoxLayout *serverLayout = new QVBoxLayout(serverGroup);

    // Статус сервера
    QHBoxLayout *serverStatusLayout = new QHBoxLayout();
    lblServerStatus = new QLabel("Сервер: <b style='color:red;'>Остановлен</b>");
    lblConnectedClients = new QLabel("Всего подключений: 0");
    serverStatusLayout->addWidget(lblServerStatus);
    serverStatusLayout->addWidget(lblConnectedClients);
    serverStatusLayout->addStretch();
    serverLayout->addLayout(serverStatusLayout);

    // Текущий IP
    QHBoxLayout *ipLayout = new QHBoxLayout();
    lblCurrentIP = new QLabel("Текущий IP: Неизвестно");
    btnCheckIP = new QPushButton("Проверить IP");
    ipLayout->addWidget(lblCurrentIP);
    ipLayout->addWidget(btnCheckIP);
    ipLayout->addStretch();
    serverLayout->addLayout(ipLayout);

    // Настройки сервера
    QFormLayout *serverConfigLayout = new QFormLayout();
    spinServerPort = new QSpinBox();
    spinServerPort->setRange(1024, 65535);
    spinServerPort->setValue(DEFAULT_VPN_SERVER_PORT);

    txtServerNetwork = new QLineEdit("10.8.0.0 255.255.255.0");
    txtServerNetwork->setPlaceholderText("сеть маска");

    chkRouteThroughTor = new QCheckBox("Маршрутизировать трафик клиентов через Tor");
    chkRouteThroughTor->setChecked(true);

    serverConfigLayout->addRow("Порт сервера:", spinServerPort);
    serverConfigLayout->addRow("Сеть клиентов:", txtServerNetwork);
    serverConfigLayout->addRow("", chkRouteThroughTor);
    serverLayout->addLayout(serverConfigLayout);

    // Кнопки управления сервером
    QHBoxLayout *serverBtnLayout = new QHBoxLayout();
    btnGenerateCerts = new QPushButton("Сгенерировать сертификаты");
    btnCheckCerts = new QPushButton("Проверить сертификаты");
    btnStartServer = new QPushButton("Запустить сервер");
    btnStopServer = new QPushButton("Остановить сервер");
    btnStopServer->setEnabled(false);
    btnGenerateClientConfig = new QPushButton("Создать клиентский .ovpn");
    btnGenerateClientConfig->setToolTip("Создать конфигурационный файл для клиента OpenVPN");

    // Новые кнопки диагностики
    btnDiagnose = new QPushButton("Диагностика");
    btnTestConfig = new QPushButton("Проверить конфиг");

    serverBtnLayout->addWidget(btnGenerateCerts);
    serverBtnLayout->addWidget(btnCheckCerts);
    serverBtnLayout->addWidget(btnStartServer);
    serverBtnLayout->addWidget(btnStopServer);
    serverBtnLayout->addWidget(btnGenerateClientConfig);
    serverBtnLayout->addWidget(btnDiagnose);
    serverBtnLayout->addWidget(btnTestConfig);
    serverBtnLayout->addStretch();
    serverLayout->addLayout(serverBtnLayout);

    // === ЖУРНАЛ СЕРВЕРА - ИСПРАВЛЕНО ===
    QGroupBox *logGroup = new QGroupBox("Журнал сервера");
    QVBoxLayout *logLayout = new QVBoxLayout(logGroup);

    txtServerLog = new QTextEdit();
    txtServerLog->setReadOnly(true);
    txtServerLog->setMaximumHeight(250);
    txtServerLog->setPlaceholderText("Здесь будет отображаться лог работы OpenVPN сервера...");
    logLayout->addWidget(txtServerLog);

    serverLayout->addWidget(logGroup);
    // ====================================

    mainLayout->addWidget(serverGroup);
    mainLayout->addStretch();
}

// ========== НОВАЯ ВКЛАДКА КЛИЕНТОВ ==========

void MainWindow::createClientsTab()
{
    clientsTab = new QWidget();
    QVBoxLayout *mainLayout = new QVBoxLayout(clientsTab);

    // Верхняя панель со статистикой
    QGroupBox *statsGroup = new QGroupBox("Статистика клиентов");
    QHBoxLayout *statsLayout = new QHBoxLayout(statsGroup);

    lblTotalClients = new QLabel("Всего подключений: <b>0</b>");
    lblActiveClients = new QLabel("Активных сейчас: <b>0</b>");

    statsLayout->addWidget(lblTotalClients);
    statsLayout->addWidget(lblActiveClients);
    statsLayout->addStretch();

    mainLayout->addWidget(statsGroup);

    // Таблица клиентов
    QGroupBox *tableGroup = new QGroupBox("Подключённые клиенты");
    QVBoxLayout *tableLayout = new QVBoxLayout(tableGroup);

    clientsTable = new QTableWidget(0, 7);
    clientsTable->setHorizontalHeaderLabels(
        QStringList() << "Имя (CN)" << "Реальный IP" << "VPN IP" << "Входящий"
        << "Исходящий" << "Подключён" << "Статус"
    );
    clientsTable->horizontalHeader()->setStretchLastSection(true);
    clientsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    clientsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    clientsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    clientsTable->setContextMenuPolicy(Qt::CustomContextMenu);
    clientsTable->setAlternatingRowColors(true);

    tableLayout->addWidget(clientsTable);
    mainLayout->addWidget(tableGroup, 2);  // Больший вес для таблицы

    // Кнопки управления клиентами
    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnRefreshClients = new QPushButton("🔄 Обновить");
    btnRefreshClients->setToolTip("Принудительное обновление списка");

    btnClientDetails = new QPushButton("ℹ️ Детали");
    btnClientDetails->setToolTip("Подробная информация о выбранном клиенте");
    btnClientDetails->setEnabled(false);

    btnDisconnectClient = new QPushButton("❌ Отключить");
    btnDisconnectClient->setToolTip("Отключить выбранного клиента");
    btnDisconnectClient->setEnabled(false);

    btnDisconnectAll = new QPushButton("⛔ Отключить всех");
    btnDisconnectAll->setToolTip("Отключить всех клиентов");

    btnBanClient = new QPushButton("🚫 Заблокировать");
    btnBanClient->setToolTip("Заблокировать клиента (добавить в CRL)");
    btnBanClient->setEnabled(false);

    btnLayout->addWidget(btnRefreshClients);
    btnLayout->addWidget(btnClientDetails);
    btnLayout->addWidget(btnDisconnectClient);
    btnLayout->addWidget(btnDisconnectAll);
    btnLayout->addWidget(btnBanClient);
    btnLayout->addStretch();

    mainLayout->addLayout(btnLayout);

    // === ЖУРНАЛ ПОДКЛЮЧЕНИЙ КЛИЕНТОВ - ИСПРАВЛЕНО ===
    QGroupBox *logGroup = new QGroupBox("Журнал подключений клиентов");
    QVBoxLayout *logLayout = new QVBoxLayout(logGroup);

    txtClientsLog = new QTextEdit();
    txtClientsLog->setReadOnly(true);
    txtClientsLog->setMaximumHeight(200);
    txtClientsLog->setPlaceholderText("Здесь будет отображаться история подключений и отключений клиентов...\n"
    "Логи сохраняются автоматически для диагностики проблем.");

    // Кнопки управления журналом
    QHBoxLayout *logBtnLayout = new QHBoxLayout();
    btnExportClientsLog = new QPushButton("💾 Экспорт");
    btnClearClientsLog = new QPushButton("🗑️ Очистить");

    // Кнопка просмотра истории
    QPushButton *btnViewHistory = new QPushButton("📜 История");
    btnViewHistory->setToolTip("Просмотр логов за предыдущие дни");
    connect(btnViewHistory, &QPushButton::clicked, this, &MainWindow::showFullClientsLog);

    logBtnLayout->addStretch();
    logBtnLayout->addWidget(btnViewHistory);
    logBtnLayout->addWidget(btnExportClientsLog);
    logBtnLayout->addWidget(btnClearClientsLog);

    logLayout->addWidget(txtClientsLog);
    logLayout->addLayout(logBtnLayout);

    mainLayout->addWidget(logGroup, 1);
    // ================================================
}

void MainWindow::createSettingsTab()
{
    settingsTab = new QWidget();
    QVBoxLayout *mainLayout = new QVBoxLayout(settingsTab);

    // Настройки Tor
    QGroupBox *torSettingsGroup = new QGroupBox("Настройки Tor");
    QFormLayout *torLayout = new QFormLayout(torSettingsGroup);

    spinTorSocksPort = new QSpinBox();
    spinTorSocksPort->setRange(1024, 65535);
    spinTorSocksPort->setValue(DEFAULT_TOR_SOCKS_PORT);

    spinTorControlPort = new QSpinBox();
    spinTorControlPort->setRange(1024, 65535);
    spinTorControlPort->setValue(DEFAULT_TOR_CONTROL_PORT);

    txtTorPath = new QLineEdit();
    btnBrowseTor = new QPushButton("Обзор...");
    QHBoxLayout *torPathLayout = new QHBoxLayout();
    torPathLayout->addWidget(txtTorPath);
    torPathLayout->addWidget(btnBrowseTor);

    torLayout->addRow("SOCKS-порт:", spinTorSocksPort);
    torLayout->addRow("Управляющий порт:", spinTorControlPort);
    torLayout->addRow("Путь к Tor:", torPathLayout);

    mainLayout->addWidget(torSettingsGroup);

    // Настройки OpenVPN
    QGroupBox *vpnSettingsGroup = new QGroupBox("Настройки OpenVPN");
    QFormLayout *vpnLayout = new QFormLayout(vpnSettingsGroup);

    txtOpenVPNPath = new QLineEdit();
    btnBrowseOpenVPN = new QPushButton("Обзор...");
    QHBoxLayout *vpnPathLayout = new QHBoxLayout();
    vpnPathLayout->addWidget(txtOpenVPNPath);
    vpnPathLayout->addWidget(btnBrowseOpenVPN);

    vpnLayout->addRow("Путь к OpenVPN:", vpnPathLayout);

    mainLayout->addWidget(vpnSettingsGroup);

    // Настройки безопасности
    QGroupBox *securityGroup = new QGroupBox("Настройки безопасности");
    QVBoxLayout *securityLayout = new QVBoxLayout(securityGroup);

    chkKillSwitch = new QCheckBox("Включить Kill Switch (блокировать весь трафик кроме Tor/VPN)");
    chkBlockIPv6 = new QCheckBox("Блокировать IPv6 трафик");
    chkDNSLeakProtection = new QCheckBox("Включить защиту от утечек DNS");

    securityLayout->addWidget(chkKillSwitch);
    securityLayout->addWidget(chkBlockIPv6);
    securityLayout->addWidget(chkDNSLeakProtection);

    mainLayout->addWidget(securityGroup);

    // Общие настройки
    QGroupBox *generalGroup = new QGroupBox("Общие настройки");
    QVBoxLayout *generalLayout = new QVBoxLayout(generalGroup);

    chkAutoStart = new QCheckBox("Автоматически запускать Tor при старте");
    chkStartMinimized = new QCheckBox("Запускать свернутым в системный трей");

    generalLayout->addWidget(chkAutoStart);
    generalLayout->addWidget(chkStartMinimized);

    mainLayout->addWidget(generalGroup);

    // Кнопка применения
    btnApplySettings = new QPushButton("Применить настройки");
    mainLayout->addWidget(btnApplySettings);
    mainLayout->addStretch();
}

void MainWindow::createLogsTab()
{
    logsTab = new QWidget();
    QVBoxLayout *mainLayout = new QVBoxLayout(logsTab);

    QHBoxLayout *controlLayout = new QHBoxLayout();

    cboLogLevel = new QComboBox();
    cboLogLevel->addItems({"Все", "Инфо", "Предупреждения", "Ошибки"});

    btnClearLogs = new QPushButton("Очистить журнал");
    btnSaveLogs = new QPushButton("Сохранить журнал");

    controlLayout->addWidget(new QLabel("Фильтр:"));
    controlLayout->addWidget(cboLogLevel);
    controlLayout->addStretch();
    controlLayout->addWidget(btnClearLogs);
    controlLayout->addWidget(btnSaveLogs);

    mainLayout->addLayout(controlLayout);

    txtAllLogs = new QTextEdit();
    txtAllLogs->setReadOnly(true);
    mainLayout->addWidget(txtAllLogs);
}

void MainWindow::setupTrayIcon()
{
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setIcon(QIcon::fromTheme("network-vpn"));

    trayMenu = new QMenu(this);
    trayMenu->addAction("Показать/Скрыть", this, [this]() {
        setVisible(!isVisible());
    });
    trayMenu->addSeparator();
    trayMenu->addAction("Запустить Tor", this, &MainWindow::startTor);
    trayMenu->addAction("Остановить Tor", this, &MainWindow::stopTor);
    trayMenu->addSeparator();
    trayMenu->addAction("Запустить VPN сервер", this, &MainWindow::startOpenVPNServer);
    trayMenu->addAction("Остановить VPN сервер", this, &MainWindow::stopOpenVPNServer);
    trayMenu->addSeparator();
    trayMenu->addAction("Выход", this, &QWidget::close);

    trayIcon->setContextMenu(trayMenu);
    trayIcon->show();

    connect(trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::onTrayActivated);
}

void MainWindow::setupConnections()
{
    // Процесс Tor
    connect(torProcess, &QProcess::started, this, &MainWindow::onTorStarted);
    connect(torProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &MainWindow::onTorFinished);
    connect(torProcess, &QProcess::errorOccurred, this, &MainWindow::onTorError);
    connect(torProcess, &QProcess::readyReadStandardOutput, this, &MainWindow::onTorReadyRead);
    connect(torProcess, &QProcess::readyReadStandardError, this, [this]() {
        QString error = QString::fromUtf8(torProcess->readAllStandardError());
        if (!error.isEmpty()) {
            addLogMessage("Tor stderr: " + error.trimmed(), "error");
        }
    });

    // Процесс сервера - ИСПРАВЛЕНО: добавлен readyRead
    connect(openVPNServerProcess, &QProcess::started, this, &MainWindow::onServerStarted);
    connect(openVPNServerProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &MainWindow::onServerFinished);
    connect(openVPNServerProcess, &QProcess::errorOccurred, this, &MainWindow::onServerError);
    // === КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ ===
    connect(openVPNServerProcess, &QProcess::readyReadStandardOutput,
            this, &MainWindow::onServerReadyRead);
    // ==========================

    // Управляющий сокет
    connect(controlSocket, &QTcpSocket::connected, this, &MainWindow::onControlSocketConnected);
    connect(controlSocket, &QTcpSocket::readyRead, this, &MainWindow::onControlSocketReadyRead);
    connect(controlSocket, &QTcpSocket::errorOccurred, this, &MainWindow::onControlSocketError);
    connect(controlSocket, &QTcpSocket::disconnected, this, [this]() {
        addLogMessage("Управляющий сокет отключен", "warning");
        controlSocketConnected = false;
    });

    // Кнопки Tor
    connect(btnStartTor, &QPushButton::clicked, this, &MainWindow::startTor);
    connect(btnStopTor, &QPushButton::clicked, this, &MainWindow::stopTor);
    connect(btnRestartTor, &QPushButton::clicked, this, &MainWindow::restartTor);
    connect(btnNewCircuit, &QPushButton::clicked, this, &MainWindow::requestNewCircuit);
    connect(btnAddBridge, &QPushButton::clicked, this, &MainWindow::addBridge);
    connect(btnRemoveBridge, &QPushButton::clicked, this, &MainWindow::removeBridge);
    connect(btnImportBridges, &QPushButton::clicked, this, &MainWindow::importBridgesFromText);
    connect(btnTestBridge, &QPushButton::clicked, this, [this]() {
        auto item = lstBridges->currentItem();
        if (item) {
            testBridgeConnection(item->text());
        }
    });
    connect(lstBridges, &QListWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        QMenu contextMenu;
        contextMenu.addAction("Проверить формат", this, &MainWindow::validateBridgeFormat);
        contextMenu.addAction("Проверить подключение", this, [this]() {
            auto item = lstBridges->currentItem();
            if (item) testBridgeConnection(item->text());
        });
            contextMenu.addSeparator();
            contextMenu.addAction("Копировать", [this]() {
                auto item = lstBridges->currentItem();
                if (item) QGuiApplication::clipboard()->setText(item->text());
            });
                contextMenu.exec(lstBridges->mapToGlobal(pos));
    });

    // Кнопки сервера
    connect(btnStartServer, &QPushButton::clicked, this, &MainWindow::startOpenVPNServer);
    connect(btnStopServer, &QPushButton::clicked, this, &MainWindow::stopOpenVPNServer);
    connect(btnGenerateCerts, &QPushButton::clicked, this, &MainWindow::generateCertificates);
    connect(btnCheckCerts, &QPushButton::clicked, this, &MainWindow::checkCertificates);
    connect(btnCheckIP, &QPushButton::clicked, this, &MainWindow::checkIPLeak);
    connect(btnGenerateClientConfig, &QPushButton::clicked, this, &MainWindow::generateClientConfig);

    // Подключаем новые кнопки диагностики
    if (btnDiagnose) {
        connect(btnDiagnose, &QPushButton::clicked, this, &MainWindow::diagnoseConnection);
    }

    if (btnTestConfig) {
        connect(btnTestConfig, &QPushButton::clicked, this, &MainWindow::testServerConfig);
    }

    // ========== НОВЫЕ ПОДКЛЮЧЕНИЯ ДЛЯ КЛИЕНТОВ ==========
    connect(clientsRefreshTimer, &QTimer::timeout, this, &MainWindow::updateClientsTable);
    connect(btnRefreshClients, &QPushButton::clicked, this, &MainWindow::refreshClientsNow);
    connect(btnDisconnectClient, &QPushButton::clicked, this, &MainWindow::disconnectSelectedClient);
    connect(btnDisconnectAll, &QPushButton::clicked, this, &MainWindow::disconnectAllClients);
    connect(btnClientDetails, &QPushButton::clicked, this, &MainWindow::showClientDetails);
    connect(btnBanClient, &QPushButton::clicked, this, &MainWindow::banClient);
    connect(btnExportClientsLog, &QPushButton::clicked, this, &MainWindow::exportClientsLog);
    connect(btnClearClientsLog, &QPushButton::clicked, this, &MainWindow::clearClientsLog);
    connect(clientsTable, &QTableWidget::customContextMenuRequested, this, &MainWindow::onClientTableContextMenu);
    connect(clientsTable, &QTableWidget::itemSelectionChanged, this, [this]() {
        bool hasSelection = !clientsTable->selectedItems().isEmpty();
        btnDisconnectClient->setEnabled(hasSelection);
        btnClientDetails->setEnabled(hasSelection);
        btnBanClient->setEnabled(hasSelection);
    });

    // Кнопки настроек
    connect(btnApplySettings, &QPushButton::clicked, this, &MainWindow::applySettings);
    connect(btnBrowseTor, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Выберите исполняемый файл Tor",
                                                    "/usr/bin", "Tor (tor)");
        if (!path.isEmpty()) {
            txtTorPath->setText(path);
            torExecutablePath = path;
        }
    });
    connect(btnBrowseOpenVPN, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Выберите исполняемый файл OpenVPN",
                                                    "/usr/sbin", "OpenVPN (openvpn)");
        if (!path.isEmpty()) {
            txtOpenVPNPath->setText(path);
            openVPNExecutablePath = path;
        }
    });

    // Кнопки журналов
    connect(btnClearLogs, &QPushButton::clicked, txtAllLogs, &QTextEdit::clear);
    connect(btnClearLogs, &QPushButton::clicked, txtTorLog, &QTextEdit::clear);
    connect(btnClearLogs, &QPushButton::clicked, txtServerLog, &QTextEdit::clear);
    connect(btnSaveLogs, &QPushButton::clicked, this, [this]() {
        QString filename = QFileDialog::getSaveFileName(this, "Сохранить журнал",
                                                        QDir::homePath() + "/tor_manager_logs.txt",
                                                        "Текстовые файлы (*.txt)");
        if (!filename.isEmpty()) {
            QFile file(filename);
            if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QTextStream out(&file);
                out << "=== ОБЩИЙ ЖУРНАЛ ===\n" << txtAllLogs->toPlainText();
                out << "\n\n=== ЖУРНАЛ TOR ===\n" << txtTorLog->toPlainText();
                out << "\n\n=== ЖУРНАЛ СЕРВЕРА ===\n" << txtServerLog->toPlainText();
                out << "\n\n=== ЖУРНАЛ КЛИЕНТОВ ===\n" << txtClientsLog->toPlainText();
                file.close();
                addLogMessage("Журнал сохранен в: " + filename, "info");
            }
        }
    });

    // Таймеры
    connect(statusTimer, &QTimer::timeout, this, &MainWindow::updateStatus);
    connect(trafficTimer, &QTimer::timeout, this, &MainWindow::updateTrafficStats);
    connect(clientStatsTimer, &QTimer::timeout, this, &MainWindow::updateClientStats);
    connect(ipCheckManager, &QNetworkAccessManager::finished, this, &MainWindow::onIPCheckFinished);
}

// ========== УПРАВЛЕНИЕ TOR ==========

void MainWindow::startTor()
{
    // Проверяем, не запущен ли уже процесс
    if (torProcess->state() == QProcess::Running) {
        addLogMessage("Tor уже запущен (процесс активен)", "warning");
        return;
    }

    if (torRunning) {
        addLogMessage("Tor уже запущен", "warning");
        return;
    }

    if (!checkTorInstalled()) {
        QMessageBox::critical(this, "Ошибка", "Tor не найден. Укажите путь в настройках.");
        return;
    }

    addLogMessage("Запуск Tor...", "info");

    createTorConfig();

    QStringList args;
    args << "-f" << torrcPath;

    torProcess->start(torExecutablePath, args);

    btnStartTor->setEnabled(false);
    btnStopTor->setEnabled(true);
}

void MainWindow::stopTor()
{
    if (!torRunning) {
        addLogMessage("Tor не запущен", "warning");
        return;
    }

    addLogMessage("Остановка Tor...", "info");

    if (controlSocketConnected) {
        sendTorCommand("SIGNAL SHUTDOWN");
    }

    QTimer::singleShot(5000, this, [this]() {
        if (torProcess->state() == QProcess::Running) {
            torProcess->kill();
        }
    });

    torRunning = false;
    controlSocketConnected = false;

    btnStartTor->setEnabled(true);
    btnStopTor->setEnabled(false);
    btnNewCircuit->setEnabled(false);

    lblTorStatus->setText("Статус: <b style='color:red;'>Отключен</b>");
    setConnectionState("disconnected");
}

void MainWindow::restartTor()
{
    addLogMessage("Перезапуск Tor...", "info");
    stopTor();
    QTimer::singleShot(2000, this, &MainWindow::startTor);
}

void MainWindow::onTorStarted()
{
    addLogMessage("Процесс Tor запущен", "info");
    torRunning = true;
    lblTorStatus->setText("Статус: <b style='color:orange;'>Подключение...</b>");

    QTimer::singleShot(3000, this, [this]() {
        controlSocket->connectToHost("127.0.0.1", spinTorControlPort->value());
    });
}

void MainWindow::onTorFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    torRunning = false;
    controlSocketConnected = false;

    QString message = QString("Процесс Tor завершен с кодом %1").arg(exitCode);
    addLogMessage(message, exitStatus == QProcess::NormalExit ? "info" : "error");

    lblTorStatus->setText("Статус: <b style='color:red;'>Отключен</b>");
    btnStartTor->setEnabled(true);
    btnStopTor->setEnabled(false);
    btnNewCircuit->setEnabled(false);

    setConnectionState("disconnected");

    if (exitStatus == QProcess::CrashExit) {
        addLogMessage("Tor аварийно завершился, попытка перезапуска через 5 секунд...", "error");
        QTimer::singleShot(5000, this, &MainWindow::startTor);
    }
}

void MainWindow::onTorError(QProcess::ProcessError error)
{
    QString errorMsg;
    switch (error) {
        case QProcess::FailedToStart:
            errorMsg = "Не удалось запустить Tor. Проверьте правильность пути к исполняемому файлу.";
            break;
        case QProcess::Crashed:
            errorMsg = "Процесс Tor аварийно завершился";
            break;
        case QProcess::Timedout:
            errorMsg = "Таймаут процесса Tor";
            break;
        default:
            errorMsg = "Неизвестная ошибка процесса Tor";
    }

    addLogMessage(errorMsg, "error");
    QMessageBox::critical(this, "Ошибка Tor", errorMsg);
}

void MainWindow::onTorReadyRead()
{
    QString output = QString::fromUtf8(torProcess->readAllStandardOutput());
    txtTorLog->append(output);
    addLogMessage("Tor: " + output.trimmed(), "info");

    if (output.contains("Bootstrapped 100%")) {
        addLogMessage("Подключение Tor установлено!", "info");
        lblTorStatus->setText("Статус: <b style='color:green;'>Подключен</b>");
        btnNewCircuit->setEnabled(true);
        setConnectionState("tor_only");
        QTimer::singleShot(2000, this, &MainWindow::requestExternalIP);
    }
}

void MainWindow::onControlSocketConnected()
{
    addLogMessage("Подключено к управляющему порту Tor", "info");
    controlSocketConnected = true;
    sendTorCommand("AUTHENTICATE \"\"");
}

void MainWindow::onControlSocketReadyRead()
{
    QString response = QString::fromUtf8(controlSocket->readAll());
    addLogMessage("Управление: " + response.trimmed(), "info");

    if (response.contains("traffic/read=")) {
        QRegularExpression re("traffic/read=(\\d+)");
        QRegularExpressionMatch match = re.match(response);
        if (match.hasMatch()) {
            bytesReceived = match.captured(1).toULongLong();
        }
    }
    if (response.contains("traffic/written=")) {
        QRegularExpression re("traffic/written=(\\d+)");
        QRegularExpressionMatch match = re.match(response);
        if (match.hasMatch()) {
            bytesSent = match.captured(1).toULongLong();
        }
    }
}

void MainWindow::onControlSocketError()
{
    addLogMessage("Ошибка управляющего сокета: " + controlSocket->errorString(), "error");
    controlSocketConnected = false;
}

void MainWindow::sendTorCommand(const QString &command)
{
    if (!controlSocketConnected) {
        addLogMessage("Нет подключения к управляющему порту", "warning");
        return;
    }

    QString cmd = command + "\r\n";
    controlSocket->write(cmd.toUtf8());
    controlSocket->flush();
}

void MainWindow::requestNewCircuit()
{
    if (!controlSocketConnected) {
        addLogMessage("Не могу запросить новую цепочку: нет подключения к управляющему порту", "warning");
        return;
    }

    addLogMessage("Запрос новой цепочки Tor...", "info");
    sendTorCommand("SIGNAL NEWNYM");

    QMessageBox::information(this, "Новая цепочка",
                             "Запрошена новая цепочка Tor. "
                             "Подождите 10 секунд перед новыми подключениями.");
}

void MainWindow::checkTorStatus()
{
    if (torRunning && controlSocketConnected) {
        sendTorCommand("GETINFO status/circuit-established");
        sendTorCommand("GETINFO traffic/read");
        sendTorCommand("GETINFO traffic/written");
    }
}

// ========== УПРАВЛЕНИЕ OPENVPN СЕРВЕРОМ ==========

void MainWindow::startOpenVPNServer()
{
    // Проверяем, не запущен ли уже процесс
    if (openVPNServerProcess->state() == QProcess::Running) {
        addLogMessage("Сервер уже запущен (процесс активен)", "warning");
        return;
    }

    if (serverMode) {
        addLogMessage("Сервер уже запущен", "warning");
        return;
    }

    if (serverStopPending) {
        addLogMessage("Сервер в процессе остановки, подождите...", "warning");
        return;
    }

    if (!checkOpenVPNInstalled()) {
        QMessageBox::critical(this, "Ошибка", "OpenVPN не найден");
        serverTorWaitRetries = 0;
        return;
    }

    // Проверяем наличие сертификатов
    if (!QFile::exists(caCertPath) || !QFile::exists(serverCertPath) ||
        !QFile::exists(serverKeyPath) || !QFile::exists(dhParamPath)) {
        QMessageBox::StandardButton reply = QMessageBox::question(this, "Сертификаты не найдены",
                                                                  "Сертификаты не найдены. Сгенерировать их сейчас?",
                                                                  QMessageBox::Yes | QMessageBox::No);

        if (reply == QMessageBox::Yes) {
            generateCertificates();
            return;
        } else {
            serverTorWaitRetries = 0;
            return;
        }
        }

        // Проверяем нужен ли Tor
        if (chkRouteThroughTor->isChecked() && !torRunning) {
            if (serverTorWaitRetries == 0) {
                addLogMessage("Запуск Tor перед стартом сервера...", "info");
                startTor();
            }

            serverTorWaitRetries++;
            if (serverTorWaitRetries > 5) {
                serverTorWaitRetries = 0;
                addLogMessage("Tor не запустился за отведённое время. Отмена старта сервера.", "error");
                QMessageBox::critical(this, "Ошибка", "Не удалось запустить Tor. Сервер не запущен.");
                return;
            }

            addLogMessage(QString("Ожидание Tor для сервера... попытка %1/5").arg(serverTorWaitRetries), "info");
            QTimer::singleShot(5000, this, &MainWindow::startOpenVPNServer);
            return;
        }

        serverTorWaitRetries = 0;

        addLogMessage("Запуск OpenVPN сервера...", "info");

        createServerConfig();

        if (!validateServerConfig()) {
            QMessageBox::critical(this, "Ошибка конфигурации",
                                  "Конфигурация сервера невалидна. Проверьте пути к сертификатам.");
            return;
        }

        QStringList args;
        args << "--config" << serverConfigPath;

        QString command = openVPNExecutablePath;
        #ifdef Q_OS_LINUX
        if (geteuid() != 0) {
            args.prepend(command);
            command = "pkexec";
        }
        #endif

        openVPNServerProcess->start(command, args);

        btnStartServer->setEnabled(false);
        btnStopServer->setEnabled(false);
}

void MainWindow::stopOpenVPNServer()
{
    if (!serverMode) {
        addLogMessage("Сервер не запущен", "warning");
        return;
    }

    if (serverStopPending) {
        addLogMessage("Сервер уже останавливается...", "warning");
        return;
    }

    addLogMessage("Остановка OpenVPN сервера...", "info");
    serverStopPending = true;

    openVPNServerProcess->terminate();

    QTimer::singleShot(5000, this, [this]() {
        if (openVPNServerProcess->state() == QProcess::Running) {
            addLogMessage("Сервер не завершился по terminate, применяем kill...", "warning");
            openVPNServerProcess->kill();
        }
    });

    btnStartServer->setEnabled(false);
    btnStopServer->setEnabled(false);
}

void MainWindow::onServerStarted()
{
    serverMode = true;
    btnStartServer->setEnabled(false);
    btnStopServer->setEnabled(true);
    addLogMessage("OpenVPN сервер запущен", "info");
    lblServerStatus->setText("Сервер: <b style='color:green;'>Запущен</b>");
    setConnectionState("server_mode");

    enableIPForwarding();
    QTimer::singleShot(1000, this, &MainWindow::checkIPLeak);

    addLogMessage("Ожидание инициализации tun-интерфейса...", "info");
    QTimer::singleShot(8000, this, [this]() {
        addLogMessage("Проверка маршрутизации после старта сервера...", "info");
        bool routingOk = false;

        QString vpnNet = txtServerNetwork->text().split(' ')[0] + "/24";
        QString checkNat = executeCommand("iptables -t nat -L POSTROUTING -n | grep " + vpnNet);
        if (!checkNat.isEmpty()) {
            addLogMessage("✓ NAT правило активно (настроено скриптом up)", "success");
            routingOk = true;
        }

        if (!routingOk) {
            addLogMessage("NAT правило не найдено, применяем вручную...", "warning");
            bool success = setupIPTablesRules(true);
            if (success) {
                addLogMessage("Маршрутизация настроена успешно (fallback)", "success");
            } else {
                addLogMessage("Ошибка настройки маршрутизации, пробуем applyRoutingManually...", "error");
                applyRoutingManually();
            }
        }

        QTimer::singleShot(3000, this, &MainWindow::verifyRouting);
    });
}

void MainWindow::onServerFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    serverMode = false;
    serverStopPending = false;

    // Читаем остаток вывода
    QString remainingOut = QString::fromUtf8(openVPNServerProcess->readAll()).trimmed();
    if (!remainingOut.isEmpty()) {
        addLogMessage("OpenVPN последний вывод:\n" + remainingOut, "info");
        // Также добавляем в txtServerLog
        if (txtServerLog) {
            txtServerLog->append("[FINISH] " + remainingOut);
        }
    }

    QString message = QString("Сервер OpenVPN завершен с кодом %1").arg(exitCode);
    addLogMessage(message, exitStatus == QProcess::NormalExit ? "info" : "error");

    if (exitCode == 1 && remainingOut.isEmpty()) {
        addLogMessage("Подсказка: запустите вручную для диагностики:", "warning");
        addLogMessage("  openvpn --config " + serverConfigPath, "warning");
        addLogMessage("  Или: cat /tmp/openvpn-server.log", "warning");
    }

    lblServerStatus->setText("Сервер: <b style='color:red;'>Остановлен</b>");
    lblConnectedClients->setText("Всего подключений: 0");
    btnStartServer->setEnabled(true);
    btnStopServer->setEnabled(false);
    connectedClients = 0;

    // Очищаем таблицу клиентов
    clientsCache.clear();
    updateClientsTable();

    setupIPTablesRules(false);

    setConnectionState(torRunning ? "tor_only" : "disconnected");
}

void MainWindow::onServerError(QProcess::ProcessError error)
{
    QString errorMsg;
    switch (error) {
        case QProcess::FailedToStart:
            errorMsg = "Не удалось запустить сервер OpenVPN";
            break;
        case QProcess::Crashed:
            errorMsg = "Сервер OpenVPN аварийно завершился";
            break;
        case QProcess::Timedout:
            errorMsg = "Таймаут сервера OpenVPN";
            break;
        default:
            errorMsg = "Неизвестная ошибка сервера";
    }

    addLogMessage(errorMsg, "error");
    QMessageBox::critical(this, "Ошибка сервера", errorMsg);
}

// ========== ИСПРАВЛЕННЫЙ МЕТОД ЧТЕНИЯ ЛОГОВ СЕРВЕРА ==========
void MainWindow::onServerReadyRead()
{
    // Читаем весь доступный вывод (stdout+stderr объединены через MergedChannels)
    QByteArray data = openVPNServerProcess->readAll();
    if (data.isEmpty()) return;

    QString output = QString::fromUtf8(data);

    // Выводим каждую строку в журнал сервера
    QStringList lines = output.split('\n');
    for (const QString &line : lines) {
        QString trimmed = line.trimmed();
        if (trimmed.isEmpty()) continue;

        // === ДОБАВЛЯЕМ В txtServerLog С TIMESTAMP ===
        QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
        QString logLine = "[" + timestamp + "] " + trimmed;

        if (txtServerLog) {
            txtServerLog->append(logLine);
        }
        // ============================================

        // Анализируем ключевые события для общего журнала
        if (trimmed.contains("Initialization Sequence Completed")) {
            addLogMessage("[OpenVPN] ✓ Сервер готов к приёму подключений!", "success");
            QTimer::singleShot(1000, this, &MainWindow::updateClientsTable);

        } else if (trimmed.contains("Peer Connection Initiated with")) {
            QRegularExpression ipRe("\\[AF_INET\\](\\S+)");
            QRegularExpressionMatch m = ipRe.match(trimmed);
            QString clientAddr = m.hasMatch() ? m.captured(1) : "?";
            addLogMessage("[OpenVPN] ✓ Клиент подключился: " + clientAddr, "success");

            // === ДОБАВЛЯЕМ В ЖУРНАЛ КЛИЕНТОВ С ПОДРОБНОСТЯМИ ===
            QString timestamp2 = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
            QString logEntry = QString("[%1] ПОДКЛЮЧЕНИЕ: %2 (инициация соединения)")
            .arg(timestamp2).arg(clientAddr);

            if (txtClientsLog) {
                txtClientsLog->append(logEntry);
            }
            // Сохраняем в файл
            saveLogToFile(logEntry, "connect");
            // ====================================================

            QTimer::singleShot(2000, this, &MainWindow::updateClientsTable);
            QTimer::singleShot(1500, this, &MainWindow::checkIPLeak);

        } else if (trimmed.contains("will cause previous active sessions")) {
            addLogMessage("[OpenVPN] Клиент переподключился (предыдущая сессия закрыта)", "info");
            QTimer::singleShot(2000, this, &MainWindow::updateClientsTable);

        } else if (trimmed.contains("client-instance exiting")) {
            addLogMessage("[OpenVPN] Клиент отключился", "info");

            // === ДОБАВЛЯЕМ В ЖУРНАЛ КЛИЕНТОВ ===
            QString timestamp2 = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
            QString logEntry = QString("[%1] ОТКЛЮЧЕНИЕ: клиент отключился").arg(timestamp2);

            if (txtClientsLog) {
                txtClientsLog->append(logEntry);
            }
            saveLogToFile(logEntry, "disconnect");
            // ===================================

            QTimer::singleShot(1500, this, &MainWindow::updateClientsTable);

        } else if (trimmed.contains("connection-reset") ||
            trimmed.contains("client-instance restarting")) {
            QTimer::singleShot(3000, this, &MainWindow::updateClientsTable);

            } else if (trimmed.contains("MULTI: bad source address")) {
                static int badSrcCount = 0;
                if (++badSrcCount <= 2)
                    addLogMessage("[OpenVPN] ⚠ bad source address (LAN-клиент, норма при старте)", "warning");

            } else if (trimmed.contains("FATAL") ||
                (trimmed.contains("ERROR") && !trimmed.contains("error:0"))) {
            addLogMessage("[OpenVPN] ✗ " + trimmed, "error");

                } else if (trimmed.contains("WARNING") &&
                   !trimmed.contains("net30") &&
                   !trimmed.contains("data-ciphers-fallback")) {
            addLogMessage("[OpenVPN] ⚠ " + trimmed, "warning");
                   }
    }

    // Автопрокрутка журнала сервера
    if (txtServerLog) {
        QTextCursor cursor = txtServerLog->textCursor();
        cursor.movePosition(QTextCursor::End);
        txtServerLog->setTextCursor(cursor);
    }
}

// ========== НОВЫЕ МЕТОДЫ ДЛЯ УПРАВЛЕНИЯ КЛИЕНТАМИ ==========

void MainWindow::updateClientsTable()
{
    if (!serverMode) {
        clientsTable->setRowCount(0);
        lblActiveClients->setText("Активных сейчас: <b>0</b>");
        return;
    }

    QFile statusFile("/tmp/openvpn-status.log");
    if (!statusFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return;
    }

    QString statusContent = QString::fromUtf8(statusFile.readAll());
    statusFile.close();

    // Парсинг status-version 2 (CSV)
    QMap<QString, ClientInfo> newClients;
    int activeCount = 0;

    for (const QString &rawLine : statusContent.split('\n')) {
        QString line = rawLine.trimmed();
        if (!line.startsWith("CLIENT_LIST,")) continue;

        QStringList p = line.split(',');
        if (p.size() < 8) continue;

        ClientInfo client;
        client.commonName = p[1].trimmed();
        client.realAddress = p[2].trimmed();
        client.virtualAddress = p[3].trimmed();
        client.virtualIPv6 = p[4].trimmed();
        client.bytesReceived = p[5].toLongLong();
        client.bytesSent = p[6].toLongLong();
        client.connectedSince = QDateTime::fromString(p[7].trimmed(), "ddd MMM d HH:mm:ss yyyy");
        client.connectedSinceEpoch = p[8].toLongLong();
        client.pid = p.size() > 9 ? p[9].toLongLong() : 0;
        client.isActive = true;

        if (client.commonName.isEmpty() || client.commonName == "UNDEF") continue;

        // Используем realAddress как уникальный ключ
        newClients[client.realAddress] = client;
        activeCount++;
    }

    // Обновляем таблицу
    clientsTable->setRowCount(newClients.size());
    int row = 0;
    qint64 totalRx = 0, totalTx = 0;

    for (auto it = newClients.begin(); it != newClients.end(); ++it) {
        const ClientInfo &client = it.value();

        // Имя (CN)
        QTableWidgetItem *nameItem = new QTableWidgetItem(client.commonName);
        nameItem->setData(Qt::UserRole, client.realAddress);  // Сохраняем ключ
        clientsTable->setItem(row, 0, nameItem);

        // Реальный IP
        clientsTable->setItem(row, 1, new QTableWidgetItem(client.realAddress));

        // VPN IP
        clientsTable->setItem(row, 2, new QTableWidgetItem(client.virtualAddress));

        // Входящий трафик
        auto fmtBytes = [](qint64 b) -> QString {
            if (b < 1024) return QString::number(b) + " B";
            if (b < 1024*1024) return QString::number(b/1024) + " KB";
            return QString::number(b/1024/1024, 'f', 2) + " MB";
        };
        clientsTable->setItem(row, 3, new QTableWidgetItem(fmtBytes(client.bytesReceived)));

        // Исходящий трафик
        clientsTable->setItem(row, 4, new QTableWidgetItem(fmtBytes(client.bytesSent)));

        // Время подключения
        QString timeStr = client.connectedSince.toString("dd.MM.yyyy HH:mm:ss");
        clientsTable->setItem(row, 5, new QTableWidgetItem(timeStr));

        // Статус
        QTableWidgetItem *statusItem = new QTableWidgetItem("🟢 Активен");
        statusItem->setBackground(QColor(200, 255, 200));
        clientsTable->setItem(row, 6, statusItem);

        totalRx += client.bytesReceived;
        totalTx += client.bytesSent;
        row++;
    }

    // Обновляем метки
    lblActiveClients->setText(QString("Активных сейчас: <b>%1</b>").arg(activeCount));
    lblTotalClients->setText(QString("Всего подключений: <b>%1</b>").arg(clientsCache.size() + newClients.size()));

    // Обновляем кэш для отслеживания изменений
    clientsCache = newClients;

    // Обновляем счётчик на вкладке сервера
    lblConnectedClients->setText(QString("Всего подключений: <b>%1</b>").arg(activeCount));
}

void MainWindow::refreshClientsNow()
{
    updateClientsTable();
    addLogMessage("Список клиентов обновлён вручную", "info");
}

void MainWindow::disconnectSelectedClient()
{
    QList<QTableWidgetItem*> selected = clientsTable->selectedItems();
    if (selected.isEmpty()) return;

    int row = selected.first()->row();
    QString cn = clientsTable->item(row, 0)->text();
    QString realAddr = clientsTable->item(row, 1)->text();

    QMessageBox::StandardButton reply = QMessageBox::question(this, "Отключение клиента",
                                                              QString("Отключить клиента '%1' (%2)?").arg(cn).arg(realAddr),
                                                              QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        QString timestamp = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
        QString logEntry = QString("[%1] ЗАПРОС ОТКЛЮЧЕНИЯ: %2 (%3)").arg(timestamp).arg(cn).arg(realAddr);

        if (txtClientsLog) {
            txtClientsLog->append(logEntry);
        }
        saveLogToFile(logEntry, "disconnect");

        addLogMessage(QString("Запрос на отключение клиента: %1 (%2)").arg(cn).arg(realAddr), "warning");
    }
}

void MainWindow::disconnectAllClients()
{
    QMessageBox::StandardButton reply = QMessageBox::question(this, "Отключение всех клиентов",
                                                              "Отключить ВСЕХ подключённых клиентов?",
                                                              QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        QString timestamp = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
        QString logEntry = QString("[%1] ЗАПРОС ОТКЛЮЧЕНИЯ ВСЕХ КЛИЕНТОВ").arg(timestamp);

        if (txtClientsLog) {
            txtClientsLog->append(logEntry);
        }
        saveLogToFile(logEntry, "disconnect");

        addLogMessage("Запрос на отключение всех клиентов", "warning");
    }
}

void MainWindow::showClientDetails()
{
    QList<QTableWidgetItem*> selected = clientsTable->selectedItems();
    if (selected.isEmpty()) return;

    int row = selected.first()->row();
    QString cn = clientsTable->item(row, 0)->text();
    QString realAddr = clientsTable->item(row, 1)->text();
    QString vpnAddr = clientsTable->item(row, 2)->text();
    QString rx = clientsTable->item(row, 3)->text();
    QString tx = clientsTable->item(row, 4)->text();
    QString since = clientsTable->item(row, 5)->text();

    QString details = QString(
        "<h3>Информация о клиенте</h3>"
        "<table>"
        "<tr><td><b>Имя (CN):</b></td><td>%1</td></tr>"
        "<tr><td><b>Реальный адрес:</b></td><td>%2</td></tr>"
        "<tr><td><b>VPN адрес:</b></td><td>%3</td></tr>"
        "<tr><td><b>Получено:</b></td><td>%4</td></tr>"
        "<tr><td><b>Отправлено:</b></td><td>%5</td></tr>"
        "<tr><td><b>Подключён с:</b></td><td>%6</td></tr>"
        "</table>"
    ).arg(cn).arg(realAddr).arg(vpnAddr).arg(rx).arg(tx).arg(since);

    QMessageBox::information(this, "Детали клиента", details);
}

void MainWindow::banClient()
{
    QList<QTableWidgetItem*> selected = clientsTable->selectedItems();
    if (selected.isEmpty()) return;

    int row = selected.first()->row();
    QString cn = clientsTable->item(row, 0)->text();

    QMessageBox::StandardButton reply = QMessageBox::warning(this, "Блокировка клиента",
                                                             QString("Заблокировать клиента '%1'?\n\n"
                                                             "Это добавит сертификат в CRL (Certificate Revocation List) "
                                                             "и клиент больше не сможет подключаться.").arg(cn),
                                                             QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        QString timestamp = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
        QString logEntry = QString("[%1] ЗАПРОС БЛОКИРОВКИ: %2").arg(timestamp).arg(cn);

        if (txtClientsLog) {
            txtClientsLog->append(logEntry);
        }
        saveLogToFile(logEntry, "ban");

        addLogMessage(QString("Запрос на блокировку клиента: %1").arg(cn), "warning");
    }
}

void MainWindow::onClientTableContextMenu(const QPoint &pos)
{
    QMenu contextMenu(this);

    contextMenu.addAction("🔍 Детали", this, &MainWindow::showClientDetails);
    contextMenu.addSeparator();
    contextMenu.addAction("❌ Отключить", this, &MainWindow::disconnectSelectedClient);
    contextMenu.addAction("🚫 Заблокировать", this, &MainWindow::banClient);
    contextMenu.addSeparator();
    contextMenu.addAction("📋 Копировать IP", [this]() {
        auto items = clientsTable->selectedItems();
        if (!items.isEmpty()) {
            QString ip = clientsTable->item(items.first()->row(), 1)->text();
            QGuiApplication::clipboard()->setText(ip);
        }
    });

    contextMenu.exec(clientsTable->mapToGlobal(pos));
}

void MainWindow::exportClientsLog()
{
    QString filename = QFileDialog::getSaveFileName(this, "Экспорт журнала клиентов",
                                                    QDir::homePath() + "/clients_log_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".txt",
                                                    "Текстовые файлы (*.txt)");

    if (filename.isEmpty()) return;

    QFile file(filename);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << "=== ЖУРНАЛ ПОДКЛЮЧЕНИЙ КЛИЕНТОВ ===\n";
        out << "Дата экспорта: " << QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss") << "\n\n";
        out << txtClientsLog->toPlainText();
        file.close();

        addLogMessage("Журнал клиентов экспортирован: " + filename, "success");
        QMessageBox::information(this, "Экспорт завершён",
                                 "Журнал клиентов сохранён:\n" + filename);
    } else {
        addLogMessage("Ошибка экспорта журнала клиентов", "error");
    }
}

void MainWindow::clearClientsLog()
{
    QMessageBox::StandardButton reply = QMessageBox::question(this, "Очистка журнала",
                                                              "Очистить журнал подключений клиентов?",
                                                              QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        txtClientsLog->clear();
        addLogMessage("Журнал клиентов очищен", "info");
    }
}

// ========== НОВЫЕ МЕТОДЫ ДЛЯ РАБОТЫ С ЛОГАМИ ==========

QString MainWindow::getLogFilePath(const QString &date)
{
    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QString logDir = appData + "/logs";
    QDir().mkpath(logDir);

    QString logDate = date.isEmpty() ? QDateTime::currentDateTime().toString("yyyy-MM-dd") : date;
    return logDir + "/clients_" + logDate + ".log";
}

void MainWindow::saveLogToFile(const QString &message, const QString &type)
{
    QString logFile = getLogFilePath();

    QFile file(logFile);
    if (file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        QTextStream out(&file);
        QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
        out << "[" << timestamp << "] [" << type.toUpper() << "] " << message << "\n";
        file.close();
    }
}

void MainWindow::loadClientsLogHistory()
{
    QString logFile = getLogFilePath();

    if (!QFile::exists(logFile)) return;

    QFile file(logFile);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return;

    QString content = file.readAll();
    file.close();

    // Показываем последние 50 строк сегодняшнего лога
    QStringList lines = content.split('\n');
    int start = qMax(0, lines.size() - 50);

    QString history;
    for (int i = start; i < lines.size(); i++) {
        if (!lines[i].isEmpty()) {
            history += lines[i] + "\n";
        }
    }

    if (txtClientsLog && !history.isEmpty()) {
        txtClientsLog->append("=== ИСТОРИЯ ЗА СЕГОДНЯ (последние 50 записей) ===");
        txtClientsLog->append(history);
        txtClientsLog->append("=== НОВЫЕ СОБЫТИЯ ===");
    }
}

void MainWindow::showFullClientsLog()
{
    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QString logDir = appData + "/logs";

    // Собираем все файлы логов
    QDir dir(logDir);
    QStringList filters;
    filters << "clients_*.log";
    QStringList files = dir.entryList(filters, QDir::Files, QDir::Name);

    if (files.isEmpty()) {
        QMessageBox::information(this, "История логов", "Файлы логов не найдены");
        return;
    }

    // Показываем диалог выбора даты
    QStringList dates;
    for (const QString &f : files) {
        QString d = f.mid(8, 10); // clients_YYYY-MM-DD.log
        dates << d;
    }

    bool ok;
    QString selected = QInputDialog::getItem(this, "Выбор даты",
                                             "Выберите дату для просмотра:", dates, dates.size() - 1, false, &ok);

    if (ok && !selected.isEmpty()) {
        QString filePath = logDir + "/clients_" + selected + ".log";
        QFile file(filePath);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString content = file.readAll();
            file.close();

            // Показываем в диалоге
            QDialog *dialog = new QDialog(this);
            dialog->setWindowTitle("Лог клиентов за " + selected);
            dialog->resize(900, 700);

            QVBoxLayout *layout = new QVBoxLayout(dialog);

            QTextEdit *textEdit = new QTextEdit(dialog);
            textEdit->setReadOnly(true);
            textEdit->setFont(QFont("Monospace", 9));
            textEdit->setPlainText(content);

            QPushButton *btnExport = new QPushButton("💾 Сохранить копию", dialog);
            connect(btnExport, &QPushButton::clicked, [this, content, selected]() {
                QString filename = QFileDialog::getSaveFileName(this, "Сохранить лог",
                                                                QDir::homePath() + "/clients_log_" + selected + ".txt",
                                                                "Текстовые файлы (*.txt)");
                if (!filename.isEmpty()) {
                    QFile f(filename);
                    if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
                        f.write(content.toUtf8());
                        f.close();
                        QMessageBox::information(this, "Успех", "Лог сохранён: " + filename);
                    }
                }
            });

            QPushButton *btnClose = new QPushButton("Закрыть", dialog);
            connect(btnClose, &QPushButton::clicked, dialog, &QDialog::accept);

            QHBoxLayout *btnLayout = new QHBoxLayout();
            btnLayout->addStretch();
            btnLayout->addWidget(btnExport);
            btnLayout->addWidget(btnClose);

            layout->addWidget(textEdit);
            layout->addLayout(btnLayout);

            dialog->exec();
        }
    }
}

void MainWindow::createServerConfig()
{
    QFile configFile(serverConfigPath);
    if (!configFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        addLogMessage("Не удалось создать конфигурацию сервера", "error");
        return;
    }

    QTextStream out(&configFile);

    out << "# OpenVPN Server Configuration\n";
    out << "# Generated by Tor Manager\n";
    out << "# Date: " << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") << "\n";
    out << "\n";

    // Базовые настройки
    out << "port " << spinServerPort->value() << "\n";
    out << "proto tcp\n";
    out << "dev tun\n";
    out << "\n";

    // Пути к сертификатам
    out << "ca " << caCertPath << "\n";
    out << "cert " << serverCertPath << "\n";
    out << "key " << serverKeyPath << "\n";
    out << "dh " << dhParamPath << "\n";

    // Настройки сети
    QStringList network = txtServerNetwork->text().split(' ');
    if (network.size() >= 2) {
        out << "server " << network[0] << " " << network[1] << "\n";
    } else {
        out << "server 10.8.0.0 255.255.255.0\n";
    }
    out << "\n";

    // Топология
    out << "topology subnet\n";
    out << "\n";

    // Настройки клиентов
    out << "client-to-client\n";
    out << "duplicate-cn\n";
    out << "keepalive 10 120\n";
    out << "max-clients 10\n";
    out << "\n";

    // client-config-dir
    QString ccdDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/ccd";
    QDir().mkpath(ccdDir);
    out << "client-config-dir " << ccdDir << "\n";
    out << "\n";

    // Настройки безопасности
    out << "tls-server\n";
    out << "tls-version-min 1.2\n";
    out << "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC\n";
    out << "data-ciphers-fallback AES-256-CBC\n";
    out << "cipher AES-256-CBC\n";
    out << "auth SHA256\n";
    out << "auth-nocache\n";
    out << "\n";

    // MTU
    out << "# MTU settings\n";
    out << "tun-mtu 1500\n";
    out << "mssfix 1350\n";
    out << "\n";

    // Хранение выданных IP
    out << "ifconfig-pool-persist /tmp/ipp.txt\n";
    out << "\n";

    // TLS-Auth ключ
    if (QFile::exists(taKeyPath)) {
        out << "tls-auth " << taKeyPath << " 0\n";
        out << "key-direction 0\n";
        out << "\n";
    }

    // Настройки маршрутизации через Tor
    if (chkRouteThroughTor && chkRouteThroughTor->isChecked()) {
        out << "push \"redirect-gateway def1 bypass-dhcp\"\n";
        out << "push \"dhcp-option DNS 10.8.0.1\"\n";
        out << "push \"dhcp-option DNS 208.67.222.222\"\n";
        out << "push \"topology subnet\"\n";
        out << "push \"tun-mtu 1500\"\n";
        out << "push \"mssfix 1350\"\n";
        out << "\n";
    }

    // Скрипты маршрутизации
    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QString upScript   = appData + "/scripts/tor-route-up.sh";
    QString downScript = appData + "/scripts/tor-route-down.sh";

    createTorRoutingScripts();

    out << "# Script security: allow calling up/down scripts\n";
    out << "script-security 2\n";
    if (QFile::exists(upScript)) {
        out << "up " << upScript << "\n";
    }
    if (QFile::exists(downScript)) {
        out << "down " << downScript << "\n";
        out << "down-pre\n";
    }
    out << "\n";

    // Дополнительные настройки
    out << "persist-key\n";
    out << "persist-tun\n";
    out << "\n";

    // Логирование
    out << "status /tmp/openvpn-status.log 5\n";
    out << "status-version 2\n";
    out << "verb 3\n";
    out << "mute 20\n";
    out << "\n";
    out << "float\n";

    configFile.close();

    addLogMessage("Конфигурация сервера создана: " + serverConfigPath, "success");
}

void MainWindow::generateClientConfig()
{
    QString clientName = QInputDialog::getText(this, "Имя клиента",
                                               "Введите имя для клиентского сертификата:",
                                               QLineEdit::Normal, "client1");

    if (clientName.isEmpty()) return;

    QString savePath = QFileDialog::getSaveFileName(this, "Сохранить конфигурацию клиента",
                                                    QDir::homePath() + "/" + clientName + ".ovpn",
                                                    "OpenVPN Config (*.ovpn)");

    if (savePath.isEmpty()) return;

    // Проверяем/создаем сертификаты для клиента
    QString clientCertFile = certsDir + "/" + clientName + ".crt";
    QString clientKeyFile = certsDir + "/" + clientName + ".key";

    if (!QFile::exists(clientCertFile) || !QFile::exists(clientKeyFile)) {
        addLogMessage("Создание сертификатов для клиента: " + clientName, "info");
        generateClientCertificate(clientName);

        QMessageBox::information(this, "Сертификаты созданы",
                                 "Сертификаты для клиента " + clientName + " созданы.\n"
                                 "Повторно нажмите кнопку создания .ovpn файла.");
        return;
    }

    QString serverAddress = "wwcat.duckdns.org";
    int serverPort = spinServerPort->value();

    QString config;
    config += "# OpenVPN Client Configuration\n";
    config += "# Generated by Tor Manager\n";
    config += "# Client: " + clientName + "\n";
    config += "# Server: " + serverAddress + ":" + QString::number(serverPort) + "\n\n";

    config += "client\n";
    config += "dev tun\n";
    config += "proto tcp\n";
    config += "remote " + serverAddress + " " + QString::number(serverPort) + "\n";
    config += "resolv-retry infinite\n";
    config += "nobind\n";
    config += "persist-key\n";
    config += "persist-tun\n\n";

    // Настройки безопасности
    config += "# Security Settings\n";
    config += "remote-cert-tls server\n";
    config += "cipher AES-256-CBC\n";
    config += "auth SHA256\n";
    config += "auth-nocache\n";
    config += "tls-version-min 1.2\n\n";

    // CA сертификат
    if (QFile::exists(caCertPath)) {
        config += "<ca>\n";
        QFile caFile(caCertPath);
        if (caFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            config += caFile.readAll();
            caFile.close();
        }
        config += "</ca>\n\n";
    }

    // Клиентский сертификат
    if (QFile::exists(clientCertFile)) {
        config += "<cert>\n";
        QFile certFile(clientCertFile);
        if (certFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString certContent = certFile.readAll();
            certFile.close();

            QRegularExpression pemRegex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----");
            QRegularExpressionMatch match = pemRegex.match(certContent);
            if (match.hasMatch()) {
                config += match.captured(0) + "\n";
            } else {
                config += certContent;
            }
        }
        config += "</cert>\n\n";
    } else {
        QMessageBox::critical(this, "Ошибка", "Клиентский сертификат не найден: " + clientCertFile);
        return;
    }

    // Клиентский ключ
    if (QFile::exists(clientKeyFile)) {
        config += "<key>\n";
        QFile keyFile(clientKeyFile);
        if (keyFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            config += keyFile.readAll();
            keyFile.close();
        }
        config += "</key>\n\n";
    } else {
        QMessageBox::critical(this, "Ошибка", "Клиентский ключ не найден: " + clientKeyFile);
        return;
    }

    // TLS-Auth ключ
    if (QFile::exists(taKeyPath)) {
        config += "key-direction 1\n";
        config += "<tls-auth>\n";
        QFile taFile(taKeyPath);
        if (taFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            config += taFile.readAll();
            taFile.close();
        }
        config += "</tls-auth>\n";
    }

    config += "\n# Verbose level\n";
    config += "verb 3\n";
    config += "mute 10\n";

    QFile file(savePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        file.write(config.toUtf8());
        file.close();
        addLogMessage("Конфигурация клиента сохранена: " + savePath, "success");

        QMessageBox::information(this, "Успех",
                                 "Конфигурация клиента сохранена.\n"
                                 "Файл: " + savePath + "\n\n"
                                 "Импортируйте этот файл в OpenVPN для Android.");
    } else {
        addLogMessage("Ошибка сохранения файла: " + savePath, "error");
        QMessageBox::critical(this, "Ошибка", "Не удалось сохранить файл конфигурации");
    }
}

void MainWindow::generateClientCertificate(const QString &clientName)
{
    addLogMessage("Генерация сертификатов для клиента: " + clientName, "info");

    QString easyRSAPath = findEasyRSA();
    if (!easyRSAPath.isEmpty()) {
        QString workDir = certsDir + "/easy-rsa";
        QDir().mkpath(workDir);

        QStringList args;
        args << "build-client-full" << clientName << "nopass";

        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert("EASYRSA_BATCH", "1");

        QProcess *process = new QProcess(this);
        process->setWorkingDirectory(workDir);
        process->setProcessEnvironment(env);

        connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                [this, process, clientName](int code, QProcess::ExitStatus) {
                    if (code == 0) {
                        QString pkiDir = certsDir + "/easy-rsa/pki";
                        QFile::copy(pkiDir + "/issued/" + clientName + ".crt",
                                    certsDir + "/" + clientName + ".crt");
                        QFile::copy(pkiDir + "/private/" + clientName + ".key",
                                    certsDir + "/" + clientName + ".key");

                        addLogMessage("Сертификаты для клиента " + clientName + " созданы", "success");
                        checkCertificates();
                    } else {
                        addLogMessage("Ошибка создания сертификатов для клиента " + clientName, "error");
                    }
                    process->deleteLater();
                });

        process->start(easyRSAPath, args);
    } else {
        addLogMessage("Используется OpenSSL для генерации клиентских сертификатов", "info");

        QProcess *genKey = new QProcess(this);
        genKey->setWorkingDirectory(certsDir);
        connect(genKey, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                [this, genKey, clientName](int code, QProcess::ExitStatus) {
                    if (code == 0) {
                        QProcess *genCsr = new QProcess(this);
                        genCsr->setWorkingDirectory(certsDir);
                        connect(genCsr, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                                [this, genCsr, clientName](int code, QProcess::ExitStatus) {
                                    if (code == 0) {
                                        QProcess *signCert = new QProcess(this);
                                        signCert->setWorkingDirectory(certsDir);
                                        connect(signCert, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                                                [this, signCert, clientName](int code, QProcess::ExitStatus) {
                                                    if (code == 0) {
                                                        addLogMessage("Сертификаты для клиента " + clientName + " созданы", "success");
                                                        checkCertificates();
                                                    } else {
                                                        addLogMessage("Ошибка подписи сертификата клиента", "error");
                                                    }
                                                    signCert->deleteLater();
                                                });

                                        signCert->start("openssl", QStringList()
                                        << "x509" << "-req"
                                        << "-in" << (certsDir + "/" + clientName + ".csr")
                                        << "-CA" << caCertPath
                                        << "-CAkey" << (certsDir + "/ca.key")
                                        << "-CAcreateserial"
                                        << "-out" << (certsDir + "/" + clientName + ".crt")
                                        << "-days" << "365"
                                        << "-outform" << "PEM");
                                    } else {
                                        addLogMessage("Ошибка генерации CSR клиента", "error");
                                    }
                                    genCsr->deleteLater();
                                });

                        genCsr->start("openssl", QStringList()
                        << "req" << "-new"
                        << "-key" << (certsDir + "/" + clientName + ".key")
                        << "-out" << (certsDir + "/" + clientName + ".csr")
                        << "-subj" << ("/C=RU/ST=Moscow/L=Moscow/O=TorManager/CN=" + clientName));
                    } else {
                        addLogMessage("Ошибка генерации ключа клиента", "error");
                    }
                    genKey->deleteLater();
                });

        genKey->start("openssl", QStringList()
        << "genrsa" << "-out"
        << (certsDir + "/" + clientName + ".key") << "2048");
    }
}

void MainWindow::createTorRoutingScripts()
{
    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(appData + "/scripts");
    QDir().mkpath(appData + "/ccd");

    QString extIf = getExternalInterface();
    QString tunNet = txtServerNetwork->text().split(' ')[0];

    // Скрипт UP
    QString upScript = appData + "/scripts/tor-route-up.sh";
    QFile upFile(upScript);
    if (upFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream s(&upFile);
        s << "#!/bin/bash\n";
        s << "# tor-route-up.sh — Auto-generated by Tor Manager\n\n";
        s << "EXT_IF=\"" << extIf << "\"\n";
        s << "[ -z \"$EXT_IF\" ] && EXT_IF=$(ip route | awk '/default/{print $5; exit}')\n";
        s << "TUN_NET=\"" << tunNet << "/24\"\n";
        s << "TOR_TRANS_PORT=9040\n";
        s << "TOR_DNS_PORT=5353\n\n";

        s << "echo \"[up] EXT_IF=$EXT_IF TUN_NET=$TUN_NET\"\n\n";

        s << "# 1. IP forwarding\n";
        s << "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1\n\n";

        s << "# 2. Очистка старых правил\n";
        s << "iptables -t nat -D POSTROUTING -s $TUN_NET -o $EXT_IF -j MASQUERADE 2>/dev/null || true\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -p tcp --syn -j REDIRECT --to-ports $TOR_TRANS_PORT 2>/dev/null || true\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -p udp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT 2>/dev/null || true\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -p tcp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT 2>/dev/null || true\n\n";

        s << "# 3. NAT\n";
        s << "iptables -t nat -A POSTROUTING -s $TUN_NET -o $EXT_IF -j MASQUERADE\n";
        s << "echo \"✓ NAT rule added successfully\"\n\n";

        s << "# 4. FORWARD правила\n";
        s << "iptables -C FORWARD -i tun+ -o $EXT_IF -j ACCEPT 2>/dev/null || \\\n";
        s << "    iptables -I FORWARD -i tun+ -o $EXT_IF -j ACCEPT\n";
        s << "iptables -C FORWARD -i $EXT_IF -o tun+ -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \\\n";
        s << "    iptables -I FORWARD -i $EXT_IF -o tun+ -m state --state ESTABLISHED,RELATED -j ACCEPT\n";
        s << "iptables -C FORWARD -s $TUN_NET -j ACCEPT 2>/dev/null || \\\n";
        s << "    iptables -I FORWARD -s $TUN_NET -j ACCEPT\n\n";

        s << "# 5. DNS → Tor DNSPort\n";
        s << "iptables -t nat -I PREROUTING -i tun+ -p udp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT\n";
        s << "iptables -t nat -I PREROUTING -i tun+ -p tcp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT\n";
        s << "echo \"✓ DNS redirected to Tor DNSPort ($TOR_DNS_PORT)\"\n\n";

        s << "# 6. TCP → Tor TransPort\n";
        s << "iptables -t nat -A PREROUTING -i tun+ -d 127.0.0.0/8    -j RETURN\n";
        s << "iptables -t nat -A PREROUTING -i tun+ -d 10.0.0.0/8     -j RETURN\n";
        s << "iptables -t nat -A PREROUTING -i tun+ -d 172.16.0.0/12  -j RETURN\n";
        s << "iptables -t nat -A PREROUTING -i tun+ -d 192.168.0.0/16 -j RETURN\n";
        s << "SERVER_TUN_IP=$(ip -4 addr show tun0 2>/dev/null | awk '/inet /{split($2,a,\"/\"); print a[1]; exit}')\n";
        s << "[ -n \"$SERVER_TUN_IP\" ] && iptables -t nat -A PREROUTING -i tun+ -d $SERVER_TUN_IP -j RETURN 2>/dev/null || true\n";
        s << "iptables -t nat -A PREROUTING -i tun+ -p tcp --syn -j REDIRECT --to-ports $TOR_TRANS_PORT\n";
        s << "echo \"✓ TCP traffic redirected to Tor TransPort ($TOR_TRANS_PORT)\"\n\n";

        s << "echo \"✓ Tor routing enabled. VPN=$TUN_NET EXT=$EXT_IF\"\n";
        upFile.close();
        QFile::setPermissions(upScript,
                              QFile::ReadOwner|QFile::WriteOwner|QFile::ExeOwner|
                              QFile::ReadGroup|QFile::ExeGroup|
                              QFile::ReadOther|QFile::ExeOther);
    }

    // Скрипт DOWN
    QString downScript = appData + "/scripts/tor-route-down.sh";
    QFile downFile(downScript);
    if (downFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream s(&downFile);
        s << "#!/bin/bash\n";
        s << "# tor-route-down.sh — Auto-generated by Tor Manager\n\n";
        s << "EXT_IF=\"" << extIf << "\"\n";
        s << "[ -z \"$EXT_IF\" ] && EXT_IF=$(ip route | awk '/default/{print $5; exit}')\n";
        s << "TUN_NET=\"" << tunNet << "/24\"\n";
        s << "TOR_TRANS_PORT=9040\n";
        s << "TOR_DNS_PORT=5353\n\n";

        s << "iptables -t nat -D POSTROUTING -s $TUN_NET -o $EXT_IF -j MASQUERADE 2>/dev/null || true\n";
        s << "iptables -D FORWARD -i tun+ -o $EXT_IF -j ACCEPT 2>/dev/null || true\n";
        s << "iptables -D FORWARD -i $EXT_IF -o tun+ -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true\n";
        s << "iptables -D FORWARD -s $TUN_NET -j ACCEPT 2>/dev/null || true\n\n";

        s << "# DNS редиректы\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -p udp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT 2>/dev/null || true\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -p tcp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT 2>/dev/null || true\n\n";

        s << "# TCP-исключения\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -d 127.0.0.0/8    -j RETURN 2>/dev/null || true\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -d 10.0.0.0/8     -j RETURN 2>/dev/null || true\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -d 172.16.0.0/12  -j RETURN 2>/dev/null || true\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -d 192.168.0.0/16 -j RETURN 2>/dev/null || true\n";
        s << "iptables -t nat -D PREROUTING -i tun+ -p tcp --syn -j REDIRECT --to-ports $TOR_TRANS_PORT 2>/dev/null || true\n\n";

        s << "echo \"✓ Tor routing disabled\"\n";
        downFile.close();
        QFile::setPermissions(downScript,
                              QFile::ReadOwner|QFile::WriteOwner|QFile::ExeOwner|
                              QFile::ReadGroup|QFile::ExeGroup|
                              QFile::ReadOther|QFile::ExeOther);
    }

    // CCD default
    QString ccdDir = appData + "/ccd";
    QFile ccdDefault(ccdDir + "/DEFAULT");
    if (ccdDefault.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream s(&ccdDefault);
        s << "# Default client config\n";
        s << "# Разрешаем трафик с реальных LAN-адресов клиента\n";
        s << "iroute 192.168.0.0 255.255.255.0\n";
        s << "iroute 192.168.1.0 255.255.255.0\n";
        s << "iroute 10.0.0.0 255.0.0.0\n";
        s << "iroute 172.16.0.0 255.240.0.0\n";
        ccdDefault.close();
    }

    addLogMessage("Скрипты маршрутизации созданы в: " + appData + "/scripts", "success");
}

// ========== МАРШРУТИЗАЦИЯ ==========

QString MainWindow::getExternalInterface()
{
    QString interface = "unknown";

    #ifdef Q_OS_LINUX
    QProcess process;
    process.start("sh", QStringList() << "-c" << "ip route | grep default | awk '{print $5}' | head -1");
    if (process.waitForFinished(3000)) {
        interface = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        if (!interface.isEmpty() && interface != "unknown") {
            addLogMessage("Определен внешний интерфейс (ip route): " + interface, "info");
            return interface;
        }
    }

    process.start("sh", QStringList() << "-c" << "route -n | grep '^0.0.0.0' | awk '{print $8}' | head -1");
    if (process.waitForFinished(3000)) {
        interface = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        if (!interface.isEmpty() && interface != "unknown") {
            addLogMessage("Определен внешний интерфейс (route): " + interface, "info");
            return interface;
        }
    }

    QStringList commonIfs = {"eth0", "enp0s3", "ens33", "enp2s0", "wlan0", "wlp2s0", "ens160"};
    for (const QString &iface : commonIfs) {
        process.start("sh", QStringList() << "-c" << "ip link show " + iface + " 2>/dev/null | grep -q UP && echo exists");
        if (process.waitForFinished(2000)) {
            QString result = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
            if (!result.isEmpty()) {
                addLogMessage("Найден активный интерфейс: " + iface, "info");
                return iface;
            }
        }
    }
    #endif

    addLogMessage("Не удалось определить внешний интерфейс, используется eth0", "warning");
    return "eth0";
}

bool MainWindow::setupIPTablesRules(bool enable)
{
    #ifdef Q_OS_LINUX
    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QString scriptPath = appData + "/scripts/" + (enable ? "tor-route-up.sh" : "tor-route-down.sh");

    if (!QFile::exists(scriptPath)) {
        createTorRoutingScripts();
    }

    if (!QFile::exists(scriptPath)) {
        addLogMessage("Скрипт маршрутизации не найден: " + scriptPath, "error");
        return false;
    }

    addLogMessage(enable ? "Настройка маршрутизации через Tor..." : "Отключение маршрутизации...", "info");

    QFile::setPermissions(scriptPath,
                          QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner |
                          QFile::ReadGroup | QFile::ExeGroup |
                          QFile::ReadOther | QFile::ExeOther);

    QProcess process;
    QStringList args;

    bool hasRoot = (geteuid() == 0);

    if (!hasRoot) {
        if (QFile::exists("/usr/bin/pkexec")) {
            args << "pkexec" << "bash" << scriptPath;
            addLogMessage("Используется pkexec для получения root прав", "info");
        } else if (QFile::exists("/usr/bin/sudo")) {
            args << "sudo" << "bash" << scriptPath;
            addLogMessage("Используется sudo для получения root прав", "info");
        } else {
            addLogMessage("Нет root прав и не найдены pkexec/sudo", "error");
            return false;
        }
    } else {
        args << "bash" << scriptPath;
    }

    addLogMessage("Выполнение команды: " + args.join(" "), "info");

    process.start(args.takeFirst(), args);

    if (!process.waitForFinished(30000)) {
        addLogMessage("Таймаут при настройке маршрутизации", "error");
        return false;
    }

    QString output = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
    QString error = QString::fromUtf8(process.readAllStandardError()).trimmed();

    if (!output.isEmpty()) {
        QStringList lines = output.split('\n');
        for (const QString &line : lines) {
            if (!line.isEmpty()) {
                if (line.contains("✓")) {
                    addLogMessage(line, "success");
                } else {
                    addLogMessage(line, "info");
                }
            }
        }
    }

    if (!error.isEmpty()) {
        addLogMessage("Ошибки выполнения: " + error, "warning");
    }

    if (process.exitCode() == 0) {
        addLogMessage("✓ Маршрутизация " + QString(enable ? "включена" : "отключена"), "success");

        if (enable) {
            QTimer::singleShot(1000, this, &MainWindow::verifyRouting);
        }

        return true;
    } else {
        addLogMessage("✗ Ошибка настройки маршрутизации (код: " +
        QString::number(process.exitCode()) + ")", "error");

        if (enable && hasRoot) {
            addLogMessage("Попытка применить правила вручную...", "info");
            applyRoutingManually();
        }

        return false;
    }
    #else
    Q_UNUSED(enable);
    return true;
    #endif
}

void MainWindow::applyRoutingManually()
{
    #ifdef Q_OS_LINUX
    QString extIf = getExternalInterface();
    QString vpnNet = txtServerNetwork->text().split(' ')[0] + "/24";

    addLogMessage("Ручное применение правил маршрутизации...", "info");

    executeCommand("sysctl -w net.ipv4.ip_forward=1");
    executeCommand("iptables -F FORWARD");
    executeCommand("iptables -t nat -F POSTROUTING");

    QString natCmd = QString("iptables -t nat -A POSTROUTING -s %1 -o %2 -j MASQUERADE")
    .arg(vpnNet).arg(extIf);
    if (executeCommand(natCmd).contains("error", Qt::CaseInsensitive)) {
        addLogMessage("Ошибка добавления NAT правила", "error");
    } else {
        addLogMessage("NAT правило добавлено", "success");
    }

    executeCommand(QString("iptables -A FORWARD -i tun+ -o %1 -j ACCEPT").arg(extIf));
    executeCommand(QString("iptables -A FORWARD -i %1 -o tun+ -m state --state ESTABLISHED,RELATED -j ACCEPT").arg(extIf));
    executeCommand("iptables -A FORWARD -i tun+ -o tun+ -j ACCEPT");
    executeCommand(QString("iptables -A FORWARD -s %1 -j ACCEPT").arg(vpnNet));
    executeCommand(QString("iptables -A FORWARD -d %1 -j ACCEPT").arg(vpnNet));

    addLogMessage("Ручное применение правил завершено", "info");

    verifyRouting();
    #endif
}

void MainWindow::verifyRouting()
{
    #ifdef Q_OS_LINUX
    addLogMessage("=== ПРОВЕРКА МАРШРУТИЗАЦИИ ===", "info");

    QFile fwdFile("/proc/sys/net/ipv4/ip_forward");
    if (fwdFile.open(QIODevice::ReadOnly)) {
        QString value = QString::fromUtf8(fwdFile.readAll()).trimmed();
        fwdFile.close();
        if (value == "1") {
            addLogMessage("✓ IP forwarding включен", "success");
        } else {
            addLogMessage("✗ IP forwarding выключен", "error");
        }
    }

    QString extIf = getExternalInterface();
    QString vpnNet = txtServerNetwork->text().split(' ')[0] + "/24";

    QString checkNat = executeCommand("iptables -t nat -L POSTROUTING -n -v | grep " + vpnNet);
    if (!checkNat.isEmpty()) {
        addLogMessage("✓ NAT правило присутствует", "success");
        QStringList lines = checkNat.split('\n');
        for (const QString &line : lines) {
            if (!line.trimmed().isEmpty()) {
                addLogMessage("  " + line.trimmed(), "info");
            }
        }
    } else {
        addLogMessage("✗ NAT правило отсутствует", "error");
    }

    QString checkForward = executeCommand("iptables -L FORWARD -n -v | grep -E 'tun|" + vpnNet + "'");
    if (!checkForward.isEmpty()) {
        addLogMessage("✓ FORWARD правила присутствуют", "success");
        QStringList lines = checkForward.split('\n');
        for (const QString &line : lines) {
            if (!line.trimmed().isEmpty()) {
                addLogMessage("  " + line.trimmed(), "info");
            }
        }
    } else {
        addLogMessage("✗ FORWARD правила отсутствуют", "error");
    }

    QString checkTun = executeCommand("ip link show | grep tun");
    if (!checkTun.isEmpty()) {
        addLogMessage("✓ TUN интерфейс активен", "success");
    }

    addLogMessage("Выполнение тестового пинга до 8.8.8.8...", "info");
    QString pingTest = executeCommand("ping -c 2 -W 2 8.8.8.8 | grep 'received'");
    if (pingTest.contains("2 received") || pingTest.contains("1 received")) {
        addLogMessage("✓ Пинг до внешнего мира работает", "success");
    } else {
        addLogMessage("✗ Пинг до внешнего мира не работает", "error");
        addLogMessage("  Возможно, проблемы с маршрутизацией", "warning");
    }

    addLogMessage("=== КОНЕЦ ПРОВЕРКИ ===", "info");
    #endif
}

void MainWindow::enableIPForwarding()
{
    #ifdef Q_OS_LINUX
    if (!checkIPForwarding()) {
        addLogMessage("Включение IP forwarding...", "info");

        QProcess process;
        if (geteuid() != 0) {
            process.start("pkexec", QStringList() << "sysctl" << "-w" << "net.ipv4.ip_forward=1");
        } else {
            process.start("sysctl", QStringList() << "-w" << "net.ipv4.ip_forward=1");
        }
        process.waitForFinished(5000);

        QProcess sedProcess;
        QString sedCmd = "sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf";
        sedCmd += " && grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || ";
        sedCmd += "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf";

        if (geteuid() != 0) {
            sedProcess.start("pkexec", QStringList() << "sh" << "-c" << sedCmd);
        } else {
            sedProcess.start("sh", QStringList() << "-c" << sedCmd);
        }
        sedProcess.waitForFinished(5000);

        if (process.exitCode() == 0) {
            addLogMessage("IP forwarding включен (временно и постоянно)", "success");
        } else {
            addLogMessage("Не удалось включить IP forwarding", "warning");
        }
    }
    #endif
}

bool MainWindow::checkIPForwarding()
{
    #ifdef Q_OS_LINUX
    QFile file("/proc/sys/net/ipv4/ip_forward");
    if (file.open(QIODevice::ReadOnly)) {
        QString value = QString::fromUtf8(file.readAll()).trimmed();
        file.close();
        return value == "1";
    }
    #endif
    return false;
}

// ========== ГЕНЕРАЦИЯ СЕРТИФИКАТОВ ==========

void MainWindow::generateCertificates()
{
    generateCertificatesAsync();
}

void MainWindow::generateCertificatesAsync()
{
    if (!certGenerator) {
        certGenerator = new CertificateGenerator(this);

        connect(certGenerator, &CertificateGenerator::logMessage,
                this, &MainWindow::addLogMessage);
        connect(certGenerator, &CertificateGenerator::finished,
                this, &MainWindow::onCertGenerationFinished);
        connect(certGenerator, &CertificateGenerator::progress,
                [this](int percent) {
                    statusBar()->showMessage(QString("Генерация сертификатов: %1%").arg(percent));
                });
    }

    bool useEasyRSA = !findEasyRSA().isEmpty();

    btnGenerateCerts->setEnabled(false);
    btnGenerateCerts->setText("Генерация...");

    certGenerator->generateCertificates(certsDir, openVPNExecutablePath, useEasyRSA);
}

void MainWindow::onCertGenerationFinished(bool success)
{
    btnGenerateCerts->setEnabled(true);
    btnGenerateCerts->setText("Сгенерировать сертификаты");
    statusBar()->showMessage("Готов");

    if (success) {
        addLogMessage("Сертификаты успешно сгенерированы!", "success");

        if (!serverMode && !serverStopPending) {
            QMessageBox::StandardButton reply = QMessageBox::question(this, "Запуск сервера",
                                                                      "Сертификаты готовы. Запустить сервер сейчас?",
                                                                      QMessageBox::Yes | QMessageBox::No);

            if (reply == QMessageBox::Yes) {
                startOpenVPNServer();
            }
        }
    } else {
        addLogMessage("Ошибка при генерации сертификатов", "error");
        QMessageBox::critical(this, "Ошибка",
                              "Не удалось сгенерировать сертификаты. Проверьте журнал.");
    }
}

void MainWindow::checkCertificates()
{
    QStringList missing;
    QStringList found;

    if (QFile::exists(caCertPath)) found << "CA сертификат";
    else missing << "CA сертификат";

    if (QFile::exists(serverCertPath)) found << "Сертификат сервера";
    else missing << "Сертификат сервера";

    if (QFile::exists(serverKeyPath)) found << "Ключ сервера";
    else missing << "Ключ сервера";

    if (QFile::exists(dhParamPath)) found << "DH параметры";
    else missing << "DH параметры";

    QString message;
    if (!found.isEmpty()) {
        message += "<b>Найдены сертификаты:</b><br>" + found.join("<br>") + "<br><br>";
    }

    if (!missing.isEmpty()) {
        message += "<b style='color:red;'>Отсутствуют:</b><br>" + missing.join("<br>") + "<br><br>";
    }

    message += "<b>Директория:</b><br>" + certsDir;

    if (missing.isEmpty()) {
        QMessageBox::information(this, "Проверка сертификатов", message);
    } else {
        QMessageBox::warning(this, "Проверка сертификатов", message);
    }
}

// ========== ПРОВЕРКА СЕТИ ==========

void MainWindow::checkIPLeak()
{
    addLogMessage("Проверка текущего IP-адреса...", "info");
    lblCurrentIP->setText("Текущий IP: <i style='color:gray;'>проверка...</i>");

    QProcess *curlProcess = new QProcess(this);
    QStringList args;

    if (torRunning) {
        args << "--socks5-hostname"
        << QString("127.0.0.1:%1").arg(spinTorSocksPort->value())
        << "--max-time" << "15"
        << "--silent"
        << "--connect-timeout" << "10"
        << "https://api.ipify.org";
        addLogMessage("Проверка IP через Tor (порт " +
        QString::number(spinTorSocksPort->value()) + ")...", "info");
    } else {
        args << "--max-time" << "10"
        << "--silent"
        << "https://api.ipify.org";
    }

    connect(curlProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, curlProcess](int exitCode, QProcess::ExitStatus) {
                QString ip = QString::fromUtf8(curlProcess->readAllStandardOutput()).trimmed();
                curlProcess->deleteLater();

                if (exitCode == 0 && !ip.isEmpty() &&
                    QRegularExpression("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$").match(ip).hasMatch()) {
                    currentIP = ip;
                torIP = ip;
                QString color = torRunning ? "#00aa00" : "#cc6600";
                QString icon  = torRunning ? "🔒 " : "🌐 ";
                QString mode  = torRunning ? " (Tor)" : " (прямой)";
                lblCurrentIP->setText("Текущий IP: <b style='color:" + color + ";'>" + icon + ip + mode + "</b>");
                lblTorIP->setText("<b style='color:" + color + ";'>" + icon + ip + "</b>");
                addLogMessage("✓ Текущий IP: " + ip + mode, "success");
                    } else {
                        addLogMessage("api.ipify.org недоступен, пробуем icanhazip.com...", "warning");
                        QProcess *fallback = new QProcess(this);
                        QStringList fbArgs;
                        fbArgs << "--max-time" << "8" << "--silent" << "https://icanhazip.com";
                        connect(fallback, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                                this, [this, fallback](int code, QProcess::ExitStatus) {
                                    QString ip2 = QString::fromUtf8(fallback->readAllStandardOutput()).trimmed();
                                    fallback->deleteLater();
                                    if (code == 0 && !ip2.isEmpty()) {
                                        currentIP = ip2;
                                        lblCurrentIP->setText("Текущий IP: <b style='color:#cc6600;'>🌐 " + ip2 + " (fallback)</b>");
                                        lblTorIP->setText("<b>🌐 " + ip2 + "</b>");
                                        addLogMessage("✓ IP (fallback): " + ip2, "info");
                                    } else {
                                        lblCurrentIP->setText("Текущий IP: <b style='color:red;'>Ошибка проверки</b>");
                                        addLogMessage("✗ Не удалось определить IP-адрес", "error");
                                    }
                                });
                        fallback->start("curl", fbArgs);
                    }
            });

    curlProcess->start("curl", args);
}

void MainWindow::onIPCheckFinished()
{
    QNetworkReply *reply = qobject_cast<QNetworkReply*>(sender());
    if (reply) reply->deleteLater();
}

void MainWindow::requestExternalIP()
{
    checkIPLeak();
}

// ========== КОНФИГУРАЦИЯ TOR ==========

void MainWindow::createTorConfig()
{
    QFile configFile(torrcPath);
    if (!configFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        addLogMessage("Не удалось создать файл конфигурации Tor", "error");
        return;
    }

    QTextStream out(&configFile);

    out << "# Tor Configuration File\n";
    out << "# Generated by Tor Manager\n\n";
    out << "DataDirectory " << torDataDir << "\n";
    out << "SocksPort " << spinTorSocksPort->value() << "\n";
    out << "ControlPort " << spinTorControlPort->value() << "\n";
    out << "CookieAuthentication 0\n\n";
    out << "Log notice file " << torDataDir << "/tor.log\n";
    out << "Log notice stdout\n\n";
    out << "AvoidDiskWrites 1\n";
    out << "HardwareAccel 1\n\n";

    if (!configuredBridges.isEmpty() && cboBridgeType->currentText() != "Нет") {
        out << "# Bridge Configuration\n";
        out << "UseBridges 1\n\n";

        QSet<QString> usedTransports;
        for (const QString &bridge : configuredBridges) {
            QString type = detectBridgeType(bridge);
            if (!type.isEmpty() && type != "unknown") {
                usedTransports.insert(type);
            }
        }

        QString lyrebirdPath = findLyrebirdPath();
        if (lyrebirdPath.isEmpty()) {
            addLogMessage("ВНИМАНИЕ: lyrebird не найден! Используются отдельные плагины.", "warning");

            if (usedTransports.contains("obfs4")) {
                out << "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n";
            }
            if (usedTransports.contains("webtunnel")) {
                out << "ClientTransportPlugin webtunnel exec /usr/bin/webtunnel\n";
            }
            if (usedTransports.contains("snowflake")) {
                out << "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client\n";
            }
        } else {
            for (const QString &transport : usedTransports) {
                out << "ClientTransportPlugin " << transport << " exec " << lyrebirdPath << "\n";
            }
        }
        out << "\n";

        out << "# Bridge lines\n";
        for (const QString &bridge : configuredBridges) {
            out << "Bridge " << normalizeBridgeLine(bridge) << "\n";
        }
        out << "\n";
    }

    out << "NumEntryGuards 3\n";
    out << "CircuitBuildTimeout 30\n\n";
    out << "ExitPolicy reject *:*\n";

    if (chkRouteThroughTor && chkRouteThroughTor->isChecked()) {
        out << "\n# Transparent Proxy for VPN server clients\n";
        out << "TransPort 0.0.0.0:9040\n";
        out << "DNSPort 0.0.0.0:5353\n";
        out << "AutomapHostsOnResolve 1\n";
        out << "VirtualAddrNetworkIPv4 10.192.0.0/10\n";
    }

    configFile.close();
    addLogMessage("Конфигурация Tor создана: " + torrcPath, "info");
}

QString MainWindow::findLyrebirdPath()
{
    QStringList possiblePaths = {
        "/usr/bin/lyrebird",
        "/usr/local/bin/lyrebird",
        "/usr/sbin/lyrebird",
        "/snap/bin/lyrebird"
    };

    QStringList fallbackPaths = {
        "/usr/bin/obfs4proxy",
        "/usr/local/bin/obfs4proxy"
    };

    for (const QString &path : possiblePaths) {
        if (QFile::exists(path)) {
            return path;
        }
    }

    QProcess which;
    which.start("which", QStringList() << "lyrebird");
    which.waitForFinished(2000);
    if (which.exitCode() == 0) {
        QString result = QString::fromUtf8(which.readAllStandardOutput()).trimmed();
        if (!result.isEmpty() && QFile::exists(result)) {
            return result;
        }
    }

    for (const QString &path : fallbackPaths) {
        if (QFile::exists(path)) {
            addLogMessage("lyrebird не найден, используется obfs4proxy", "warning");
            return path;
        }
    }

    return QString();
}

bool MainWindow::checkTorInstalled()
{
    if (torExecutablePath.isEmpty()) {
        QStringList possiblePaths = {
            "/usr/bin/tor",
            "/usr/local/bin/tor",
            "/usr/sbin/tor"
        };

        for (const QString &path : possiblePaths) {
            if (QFile::exists(path)) {
                torExecutablePath = path;
                txtTorPath->setText(path);
                return true;
            }
        }
        return false;
    }

    return QFile::exists(torExecutablePath);
}

bool MainWindow::checkOpenVPNInstalled()
{
    if (openVPNExecutablePath.isEmpty()) {
        QStringList possiblePaths = {
            "/usr/sbin/openvpn",
            "/usr/bin/openvpn",
            "/usr/local/sbin/openvpn"
        };

        for (const QString &path : possiblePaths) {
            if (QFile::exists(path)) {
                openVPNExecutablePath = path;
                txtOpenVPNPath->setText(path);
                return true;
            }
        }
        return false;
    }

    return QFile::exists(openVPNExecutablePath);
}

// ========== УПРАВЛЕНИЕ МОСТАМИ ==========

void MainWindow::addBridge()
{
    QString bridgeType = cboBridgeType->currentText();
    if (bridgeType == "Нет") {
        QMessageBox::information(this, "Информация", "Пожалуйста, выберите тип моста сначала.");
        return;
    }

    QString actualType = bridgeType;
    if (bridgeType == "obfs4 (lyrebird)") actualType = "obfs4";
    else if (bridgeType == "Автоопределение") actualType = "auto";

    QString hint;
    if (actualType == "obfs4") {
        hint = "Пример: obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=... iat-mode=0";
    } else if (actualType == "webtunnel") {
        hint = "Пример: webtunnel [2001:db8::1]:443 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://... ver=0.0.3";
    } else if (actualType == "snowflake") {
        hint = "Пример: snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72";
    } else {
        hint = "Введите строку моста (формат определится автоматически)";
    }

    bool ok;
    QString bridge = QInputDialog::getMultiLineText(this, "Добавить мост",
                                                    "Введите строку моста:\n\n" + hint,
                                                    "", &ok);

    if (ok && !bridge.isEmpty()) {
        QStringList lines = bridge.split('\n', Qt::SkipEmptyParts);
        int added = 0;

        for (QString line : lines) {
            line = line.trimmed();
            if (line.isEmpty()) continue;

            QString detectedType = detectBridgeType(line);
            bool valid = false;

            if (detectedType == "obfs4") {
                valid = validateObfs4Bridge(line);
            } else if (detectedType == "webtunnel") {
                valid = validateWebtunnelBridge(line);
            } else if (detectedType != "unknown") {
                valid = true;
            }

            if (valid || detectedType != "unknown") {
                QString normalized = normalizeBridgeLine(line);
                if (!configuredBridges.contains(normalized)) {
                    configuredBridges.append(normalized);
                    lstBridges->addItem(normalized);
                    added++;
                }
            } else {
                addLogMessage("Неверный формат моста: " + line.left(50) + "...", "error");
            }
        }

        updateBridgeStats();
        saveBridgesToSettings();

        if (added > 0) {
            addLogMessage(QString("Добавлено мостов: %1").arg(added), "info");

            if (torRunning) {
                if (QMessageBox::question(this, "Перезапуск Tor",
                    "Мосты добавлены. Перезапустить Tor для применения изменений?") == QMessageBox::Yes) {
                    restartTor();
                    }
            }
        }
    }
}

void MainWindow::removeBridge()
{
    QList<QListWidgetItem*> items = lstBridges->selectedItems();
    if (items.isEmpty()) {
        QMessageBox::information(this, "Информация", "Выберите мост для удаления.");
        return;
    }

    for (QListWidgetItem *item : items) {
        QString bridge = item->text();
        configuredBridges.removeAll(bridge);
        delete item;
    }

    updateBridgeStats();
    saveBridgesToSettings();

    if (torRunning) {
        if (QMessageBox::question(this, "Перезапуск Tor",
            "Мосты удалены. Перезапустить Tor для применения изменений?") == QMessageBox::Yes) {
            restartTor();
            }
    }
}

void MainWindow::importBridgesFromText()
{
    bool ok;
    QString text = QInputDialog::getMultiLineText(this, "Импорт мостов",
                                                  "Вставьте строки мостов (по одной на строку):\n\n"
                                                  "Примеры:\n"
                                                  "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=... iat-mode=0\n"
                                                  "webtunnel [2001:db8::1]:443 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://... ver=0.0.3\n"
                                                  "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72",
                                                  "", &ok);

    if (!ok || text.isEmpty()) return;

    QStringList lines = text.split('\n', Qt::SkipEmptyParts);
    int added = 0;

    for (QString line : lines) {
        line = line.trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;

        QString bridgeType = detectBridgeType(line);
        if (bridgeType == "unknown") continue;

        bool valid = false;
        if (bridgeType == "obfs4") {
            valid = validateObfs4Bridge(line);
        } else if (bridgeType == "webtunnel") {
            valid = validateWebtunnelBridge(line);
        } else {
            valid = true;
        }

        if (valid) {
            QString normalized = normalizeBridgeLine(line);
            if (!configuredBridges.contains(normalized)) {
                configuredBridges.append(normalized);
                lstBridges->addItem(normalized);
                added++;
            }
        }
    }

    updateBridgeStats();
    saveBridgesToSettings();

    if (added > 0 && torRunning) {
        if (QMessageBox::question(this, "Перезапуск Tor",
            "Мосты добавлены. Перезапустить Tor для применения изменений?") == QMessageBox::Yes) {
            restartTor();
            }
    }
}

void MainWindow::validateBridgeFormat()
{
    auto item = lstBridges->currentItem();
    if (!item) {
        QMessageBox::information(this, "Информация", "Выберите мост для проверки.");
        return;
    }

    QString bridge = item->text();
    QString bridgeType = detectBridgeType(bridge);
    bool valid = false;
    QString message;

    if (bridgeType == "obfs4") {
        valid = validateObfs4Bridge(bridge);
        message = valid ? "✓ obfs4 мост имеет правильный формат" : "✗ obfs4 мост имеет неверный формат";
    } else if (bridgeType == "webtunnel") {
        valid = validateWebtunnelBridge(bridge);
        message = valid ? "✓ webtunnel мост имеет правильный формат" : "✗ webtunnel мост имеет неверный формат";
    } else if (bridgeType == "snowflake") {
        message = "✓ snowflake мост (формат не проверялся)";
        valid = true;
    } else {
        message = "✗ Неизвестный тип моста";
    }

    QMessageBox::information(this, "Результат проверки", message);

    if (valid) {
        item->setBackground(QColor(200, 255, 200));
    } else {
        item->setBackground(QColor(255, 200, 200));
    }
}

void MainWindow::testBridgeConnection(const QString &bridge)
{
    addLogMessage("Тестирование моста: " + bridge.left(50) + "...", "info");

    QString bridgeType = detectBridgeType(bridge);
    if (bridgeType == "unknown") {
        addLogMessage("Неизвестный тип моста", "error");
        return;
    }

    if (!checkTransportPluginInstalled(bridgeType)) {
        QString message = QString("Плагин транспорта %1 не найден.\n").arg(bridgeType);
        message += "Установите lyrebird для поддержки всех транспортов.";
        QMessageBox::warning(this, "Транспорт не найден", message);
        return;
    }

    QStringList parts = bridge.split(' ');
    if (parts.size() >= 2) {
        QString address = parts[1];
        if (address.contains(':')) {
            QString host = address.left(address.indexOf(':'));
            if (host.startsWith('[')) {
                host = host.mid(1, host.length() - 2);
            }

            #ifdef Q_OS_LINUX
            QProcess ping;
            if (host.contains(':')) {
                ping.start("ping6", QStringList() << "-c" << "2" << "-W" << "2" << host);
            } else {
                ping.start("ping", QStringList() << "-c" << "2" << "-W" << "2" << host);
            }
            ping.waitForFinished(5000);
            if (ping.exitCode() == 0) {
                addLogMessage("✓ Хост доступен", "success");
            } else {
                addLogMessage("✗ Хост недоступен", "warning");
            }
            #endif
        }
    }
}

void MainWindow::updateBridgeConfig()
{
    if (torRunning) {
        if (QMessageBox::question(this, "Требуется перезапуск",
            "Конфигурация мостов изменена. Перезапустить Tor для применения изменений?") == QMessageBox::Yes) {
            restartTor();
            }
    } else {
        createTorConfig();
    }
}

QString MainWindow::detectBridgeType(const QString &bridgeLine)
{
    QString line = bridgeLine.trimmed();

    if (line.startsWith("obfs4", Qt::CaseInsensitive)) {
        return "obfs4";
    } else if (line.startsWith("webtunnel", Qt::CaseInsensitive)) {
        return "webtunnel";
    } else if (line.startsWith("snowflake", Qt::CaseInsensitive)) {
        return "snowflake";
    }

    if (line.contains("cert=") && line.contains("iat-mode=")) {
        return "obfs4";
    } else if (line.contains("url=") && line.contains("ver=")) {
        return "webtunnel";
    }

    return "unknown";
}

bool MainWindow::validateWebtunnelBridge(const QString &bridge)
{
    QString line = bridge.trimmed();
    if (line.startsWith("webtunnel ", Qt::CaseInsensitive)) {
        line = line.mid(10).trimmed();
    }

    QStringList parts = line.split(' ', Qt::SkipEmptyParts);
    if (parts.size() < 3) return false;

    QString address = parts[0];
    QRegularExpression ipv6Regex("^\\[[0-9a-fA-F:]+\\]:\\d+$");
    QRegularExpression ipv4Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+$");

    if (!ipv6Regex.match(address).hasMatch() && !ipv4Regex.match(address).hasMatch()) {
        return false;
    }

    bool hasUrl = false;
    bool hasVer = false;

    for (int i = 2; i < parts.size(); i++) {
        if (parts[i].startsWith("url=")) hasUrl = true;
        if (parts[i].startsWith("ver=")) hasVer = true;
    }

    return hasUrl && hasVer;
}

bool MainWindow::validateObfs4Bridge(const QString &bridge)
{
    QString line = bridge.trimmed();
    if (line.startsWith("obfs4 ", Qt::CaseInsensitive)) {
        line = line.mid(6).trimmed();
    }

    QStringList parts = line.split(' ', Qt::SkipEmptyParts);
    if (parts.size() < 3) return false;

    bool hasCert = false;
    for (int i = 2; i < parts.size(); i++) {
        if (parts[i].startsWith("cert=")) {
            hasCert = true;
            break;
        }
    }

    return hasCert;
}

QString MainWindow::normalizeBridgeLine(const QString &bridge)
{
    QString normalized = bridge.trimmed().simplified();
    QString detectedType = detectBridgeType(normalized);

    if (detectedType == "webtunnel" && !normalized.startsWith("webtunnel")) {
        normalized = "webtunnel " + normalized;
    } else if (detectedType == "obfs4" && !normalized.startsWith("obfs4")) {
        normalized = "obfs4 " + normalized;
    } else if (detectedType == "snowflake" && !normalized.startsWith("snowflake")) {
        normalized = "snowflake " + normalized;
    }

    return normalized;
}

void MainWindow::updateBridgeStats()
{
    int count = configuredBridges.size();
    lblBridgeStats->setText(QString("Мосты: %1 настроено").arg(count));
}

void MainWindow::saveBridgesToSettings()
{
    settings->setValue("tor/bridges", configuredBridges);
    settings->setValue("tor/bridgeType", cboBridgeType->currentText());
    settings->sync();
}

void MainWindow::loadBridgesFromSettings()
{
    configuredBridges = settings->value("tor/bridges").toStringList();
    lstBridges->clear();
    lstBridges->addItems(configuredBridges);

    QString bridgeType = settings->value("tor/bridgeType", "Нет").toString();
    int index = cboBridgeType->findText(bridgeType);
    if (index >= 0) {
        cboBridgeType->setCurrentIndex(index);
    }

    updateBridgeStats();
}

bool MainWindow::checkTransportPluginInstalled(const QString &transport)
{
    QString lyrebirdPath = findLyrebirdPath();
    if (!lyrebirdPath.isEmpty()) {
        transportPluginPaths[transport] = lyrebirdPath;
        return true;
    }

    QStringList possiblePaths;
    if (transport == "obfs4") {
        possiblePaths << "/usr/bin/obfs4proxy" << "/usr/local/bin/obfs4proxy";
    } else if (transport == "webtunnel") {
        possiblePaths << "/usr/bin/webtunnel" << "/usr/local/bin/webtunnel";
    } else if (transport == "snowflake") {
        possiblePaths << "/usr/bin/snowflake-client" << "/usr/local/bin/snowflake-client";
    }

    for (const QString &path : possiblePaths) {
        if (QFile::exists(path)) {
            transportPluginPaths[transport] = path;
            return true;
        }
    }

    return false;
}

QString MainWindow::getTransportPluginPath(const QString &transport)
{
    return transportPluginPaths.value(transport);
}

// ========== KILL SWITCH ==========

void MainWindow::enableKillSwitch()
{
    addLogMessage("Включение kill switch...", "info");
    setupFirewallRules(true);
    killSwitchEnabled = true;

    trayIcon->showMessage("Kill Switch",
                          "Kill switch включен. Весь трафик кроме Tor будет заблокирован.",
                          QSystemTrayIcon::Information, 3000);
}

void MainWindow::disableKillSwitch()
{
    addLogMessage("Отключение kill switch...", "info");
    setupFirewallRules(false);
    killSwitchEnabled = false;
}

void MainWindow::setupFirewallRules(bool enable)
{
    #ifdef Q_OS_LINUX
    if (enable) {
        QStringList rules = {
            "iptables -F OUTPUT",
            "iptables -P OUTPUT DROP",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            QString("iptables -A OUTPUT -p tcp --dport %1 -j ACCEPT").arg(spinTorSocksPort->value()),
            QString("iptables -A OUTPUT -p tcp --dport %1 -j ACCEPT").arg(spinTorControlPort->value()),
            "iptables -A OUTPUT -o tun+ -j ACCEPT",
            "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
        };

        if (chkBlockIPv6->isChecked()) {
            rules.append("ip6tables -P OUTPUT DROP");
        }

        for (const QString &rule : rules) {
            executeCommand("pkexec sh -c '" + rule + "'");
        }
    } else {
        QStringList rules = {
            "iptables -F OUTPUT",
            "iptables -P OUTPUT ACCEPT",
            "ip6tables -P OUTPUT ACCEPT"
        };

        for (const QString &rule : rules) {
            executeCommand("pkexec sh -c '" + rule + "'");
        }
    }
    #else
    Q_UNUSED(enable);
    #endif
}

// ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

QString MainWindow::findEasyRSA()
{
    QStringList paths = {
        "/usr/share/easy-rsa/easyrsa",
        "/usr/local/share/easy-rsa/easyrsa",
        "/usr/bin/easyrsa"
    };

    for (const QString &path : paths) {
        if (QFile::exists(path)) {
            return path;
        }
    }

    return QString();
}

QString MainWindow::getLocalIP()
{
    QString ip;
    #ifdef Q_OS_LINUX
    ip = executeCommand("hostname -I | awk '{print $1}'").trimmed();
    #endif

    if (ip.isEmpty()) {
        QTcpSocket socket;
        socket.connectToHost("8.8.8.8", 53);
        if (socket.waitForConnected(3000)) {
            ip = socket.localAddress().toString();
            socket.disconnectFromHost();
        }
    }

    return ip;
}

void MainWindow::updateClientStats()
{
    // Устаревший метод, заменён на updateClientsTable
    updateClientsTable();
}

bool MainWindow::isProcessRunning(const QString &processName)
{
    #ifdef Q_OS_LINUX
    QProcess process;
    process.start("pgrep", QStringList() << "-x" << processName);
    process.waitForFinished();
    return process.exitCode() == 0;
    #else
    Q_UNUSED(processName);
    return false;
    #endif
}

QString MainWindow::executeCommand(const QString &command)
{
    QProcess process;
    #ifdef Q_OS_LINUX
    if (geteuid() != 0 && !command.startsWith("pkexec") && !command.startsWith("sudo")) {
        if (QFile::exists("/usr/bin/pkexec")) {
            process.start("pkexec", QStringList() << "sh" << "-c" << command);
        } else if (QFile::exists("/usr/bin/sudo")) {
            process.start("sudo", QStringList() << "sh" << "-c" << command);
        } else {
            process.start("sh", QStringList() << "-c" << command);
        }
    } else {
        process.start("sh", QStringList() << "-c" << command);
    }
    #else
    process.start("sh", QStringList() << "-c" << command);
    #endif

    if (!process.waitForFinished(30000)) {
        return QString();
    }

    return QString::fromUtf8(process.readAllStandardOutput()).trimmed();
}

void MainWindow::setConnectionState(const QString &state)
{
    currentConnectionState = state;

    if (state == "disconnected") {
        statusBar()->showMessage("Отключено");
        statusBar()->setStyleSheet("");
    } else if (state == "tor_only") {
        statusBar()->showMessage("Подключено: Только Tor");
        statusBar()->setStyleSheet("background-color: orange; color: white;");
    } else if (state == "server_mode") {
        statusBar()->showMessage("Режим сервера");
        statusBar()->setStyleSheet("background-color: blue; color: white;");
    }

    addLogMessage("Состояние подключения: " + state, "info");
}

bool MainWindow::verifyTorConnection()
{
    if (!torRunning) return false;

    QTcpSocket testSocket;
    testSocket.connectToHost("127.0.0.1", spinTorSocksPort->value());

    if (testSocket.waitForConnected(3000)) {
        testSocket.disconnectFromHost();
        return true;
    }

    return false;
}

void MainWindow::updateStatus()
{
    if (torRunning && verifyTorConnection()) {
        lblTorStatus->setText("Статус: <b style='color:green;'>Подключен</b>");
    } else if (torRunning) {
        lblTorStatus->setText("Статус: <b style='color:orange;'>Запуск...</b>");
    } else {
        lblTorStatus->setText("Статус: <b style='color:red;'>Отключен</b>");
    }

    if (serverMode) {
        setConnectionState("server_mode");
    } else if (torRunning) {
        setConnectionState("tor_only");
    } else {
        setConnectionState("disconnected");
    }
}

void MainWindow::updateTrafficStats()
{
    if (!controlSocketConnected) return;

    sendTorCommand("GETINFO traffic/read");
    sendTorCommand("GETINFO traffic/written");

    QString readableRx = QString::number(bytesReceived / 1024.0, 'f', 2) + " КБ";
    QString readableTx = QString::number(bytesSent / 1024.0, 'f', 2) + " КБ";

    if (bytesReceived > 1024 * 1024) {
        readableRx = QString::number(bytesReceived / (1024.0 * 1024.0), 'f', 2) + " МБ";
    }
    if (bytesSent > 1024 * 1024) {
        readableTx = QString::number(bytesSent / (1024.0 * 1024.0), 'f', 2) + " МБ";
    }

    lblTrafficStats->setText("Трафик: ↓ " + readableRx + " ↑ " + readableTx);
}

void MainWindow::addLogMessage(const QString &message, const QString &type)
{
    QString timestamp = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
    QString color;
    QString typeStr;

    if (type == "error") {
        color = "red";
        typeStr = "ОШИБКА";
    } else if (type == "warning") {
        color = "orange";
        typeStr = "ПРЕДУПРЕЖДЕНИЕ";
    } else if (type == "info") {
        color = "blue";
        typeStr = "ИНФО";
    } else if (type == "success") {
        color = "green";
        typeStr = "УСПЕХ";
    } else {
        color = "black";
        typeStr = "ЛОГ";
    }

    QString formattedMsg = QString("<span style='color:%1;'>[%2] [%3] %4</span><br>")
    .arg(color)
    .arg(timestamp)
    .arg(typeStr)
    .arg(message.toHtmlEscaped());

    txtAllLogs->append(formattedMsg);

    QTextCursor cursor = txtAllLogs->textCursor();
    cursor.movePosition(QTextCursor::End);
    txtAllLogs->setTextCursor(cursor);

    if (txtAllLogs->document()->lineCount() > MAX_LOG_LINES) {
        QTextCursor removeCursor(txtAllLogs->document());
        removeCursor.movePosition(QTextCursor::Start);
        removeCursor.movePosition(QTextCursor::Down, QTextCursor::KeepAnchor, 1000);
        removeCursor.removeSelectedText();
    }

    // === СОХРАНЯЕМ В ФАЙЛ ДЛЯ ДИАГНОСТИКИ ===
    saveLogToFile(message, type);
}

// ========== НАСТРОЙКИ ==========

void MainWindow::loadSettings()
{
    if (!settings) return;

    spinTorSocksPort->setValue(settings->value("tor/socksPort", DEFAULT_TOR_SOCKS_PORT).toInt());
    spinTorControlPort->setValue(settings->value("tor/controlPort", DEFAULT_TOR_CONTROL_PORT).toInt());

    torExecutablePath = settings->value("tor/executablePath", "/usr/bin/tor").toString();
    txtTorPath->setText(torExecutablePath);

    openVPNExecutablePath = settings->value("vpn/executablePath", "/usr/sbin/openvpn").toString();
    txtOpenVPNPath->setText(openVPNExecutablePath);

    chkKillSwitch->setChecked(settings->value("security/killSwitch", false).toBool());
    chkBlockIPv6->setChecked(settings->value("security/blockIPv6", true).toBool());
    chkDNSLeakProtection->setChecked(settings->value("security/dnsProtection", true).toBool());

    chkAutoStart->setChecked(settings->value("general/autoStart", false).toBool());
    chkStartMinimized->setChecked(settings->value("general/startMinimized", false).toBool());

    spinServerPort->setValue(settings->value("server/port", DEFAULT_VPN_SERVER_PORT).toInt());
    txtServerNetwork->setText(settings->value("server/network", "10.8.0.0 255.255.255.0").toString());
    chkRouteThroughTor->setChecked(settings->value("server/routeThroughTor", true).toBool());

    loadBridgesFromSettings();
}

void MainWindow::saveSettings()
{
    settings->setValue("tor/socksPort", spinTorSocksPort->value());
    settings->setValue("tor/controlPort", spinTorControlPort->value());
    settings->setValue("tor/executablePath", txtTorPath->text());

    settings->setValue("vpn/executablePath", txtOpenVPNPath->text());

    settings->setValue("security/killSwitch", chkKillSwitch->isChecked());
    settings->setValue("security/blockIPv6", chkBlockIPv6->isChecked());
    settings->setValue("security/dnsProtection", chkDNSLeakProtection->isChecked());

    settings->setValue("general/autoStart", chkAutoStart->isChecked());
    settings->setValue("general/startMinimized", chkStartMinimized->isChecked());

    settings->setValue("server/port", spinServerPort->value());
    settings->setValue("server/network", txtServerNetwork->text());
    settings->setValue("server/routeThroughTor", chkRouteThroughTor->isChecked());

    saveBridgesToSettings();
    settings->sync();
}

void MainWindow::applySettings()
{
    saveSettings();

    torExecutablePath = txtTorPath->text();
    openVPNExecutablePath = txtOpenVPNPath->text();

    QMessageBox::information(this, "Настройки", "Настройки успешно применены.");

    if (chkKillSwitch->isChecked() && !killSwitchEnabled) {
        enableKillSwitch();
    } else if (!chkKillSwitch->isChecked() && killSwitchEnabled) {
        disableKillSwitch();
    }

    if (torRunning) {
        if (QMessageBox::question(this, "Перезапуск Tor",
            "Некоторые настройки требуют перезапуска Tor. Перезапустить сейчас?") == QMessageBox::Yes) {
            restartTor();
            }
    } else {
        createTorConfig();
    }
}

// ========== СЛОТЫ ИНТЕРФЕЙСА ==========

void MainWindow::showSettings()
{
    tabWidget->setCurrentWidget(settingsTab);
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, "О программе Tor Manager",
                       "<h2>Tor Manager с OpenVPN</h2>"
                       "<p>Версия 1.2</p>"
                       "<p>Приложение на Qt для управления Tor с интегрированной поддержкой OpenVPN сервера.</p>"
                       "<p><b>Возможности:</b></p>"
                       "<ul>"
                       "<li>Запуск/Остановка Tor с пользовательской конфигурацией</li>"
                       "<li>OpenVPN сервер с маршрутизацией трафика через Tor</li>"
                       "<li><b>Управление клиентами — отдельная вкладка с таблицей и журналом</b></li>"
                       "<li>Поддержка мостов (obfs4/lyrebird, webtunnel, snowflake)</li>"
                       "<li>Поддержка IPv6 адресов для webtunnel мостов</li>"
                       "<li>Автоматическая генерация сертификатов</li>"
                       "<li>Kill switch для защиты от утечек</li>"
                       "<li>Мониторинг трафика и клиентов</li>"
                       "<li>Обнаружение утечек IP</li>"
                       "<li>Импорт списков мостов</li>"
                       "<li>Диагностика сервера</li>"
                       "<li>Проверка конфигурации</li>"
                       "<li>Автоматическая настройка маршрутизации</li>"
                       "<li>Проверка и восстановление правил iptables</li>"
                       "<li><b>Сохранение логов клиентов в файлы для диагностики</b></li>"
                       "</ul>"
                       "<p>Создано с использованием Qt и C++</p>"
                       "<p>© 2026 Проект Tor Manager</p>");
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick) {
        setVisible(!isVisible());
        if (isVisible()) {
            activateWindow();
            raise();
        }
    }
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (trayIcon->isVisible()) {
        hide();
        event->ignore();
        trayIcon->showMessage("Tor Manager",
                              "Приложение продолжает работу в системном трее.",
                              QSystemTrayIcon::Information, 2000);
    }
}

// ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

bool MainWindow::copyPath(const QString &src, const QString &dst)
{
    QDir dir(src);
    if (!dir.exists())
        return false;

    QDir().mkpath(dst);

    foreach (QString d, dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        QString dst_path = dst + QDir::separator() + d;
        copyPath(src + QDir::separator() + d, dst_path);
    }

    foreach (QString f, dir.entryList(QDir::Files)) {
        QFile::copy(src + QDir::separator() + f, dst + QDir::separator() + f);
    }

    return true;
}

// ========== ДИАГНОСТИКА ==========

void MainWindow::diagnoseConnection()
{
    addLogMessage("=== ДИАГНОСТИКА ПОДКЛЮЧЕНИЯ ===", "info");

    QString telnetTest = executeCommand("timeout 2 telnet 127.0.0.1 " +
    QString::number(spinServerPort->value()) +
    " 2>&1 || true");

    QString portTestResult = telnetTest.contains("Connected") ? "УСПЕХ" : "НЕУДАЧА";
    addLogMessage("Локальный тест порта: " + portTestResult,
                  telnetTest.contains("Connected") ? "success" : "error");

    QString externalIP = executeCommand("curl -s ifconfig.me || curl -s icanhazip.com || echo 'Не удалось определить'");
    addLogMessage("Внешний IP сервера: " + externalIP, "info");

    QString iptables = executeCommand("iptables -L -n | grep -E '(ACCEPT|DROP)' || echo 'Нет правил или нет доступа'");
    addLogMessage("Правила firewall:\n" + iptables, "info");

    QString portCheck = executeCommand("ss -tlnp | grep :" +
    QString::number(spinServerPort->value()) +
    " || echo 'Порт не прослушивается'");
    addLogMessage("Прослушивание порта:\n" + portCheck,
                  portCheck.contains("openvpn") ? "success" : "warning");

    // Проверяем логи клиентов
    QString logFile = getLogFilePath();
    if (QFile::exists(logFile)) {
        QFileInfo fi(logFile);
        addLogMessage("Файл логов клиентов: " + logFile + " (" +
        QString::number(fi.size() / 1024) + " KB)", "info");
    }

    QString logFile2 = "/tmp/openvpn-server.log";
    if (QFile::exists(logFile2)) {
        QFile file(logFile2);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString content = file.readAll();
            QStringList errors;
            QStringList lines = content.split('\n');
            for (const QString &line : lines) {
                if (line.contains("error", Qt::CaseInsensitive) ||
                    line.contains("fail", Qt::CaseInsensitive) ||
                    line.contains("TLS", Qt::CaseInsensitive) ||
                    line.contains("SSL", Qt::CaseInsensitive)) {
                    errors << line;
                    }
            }
            if (!errors.isEmpty()) {
                addLogMessage("Ошибки в логе OpenVPN:", "error");
                for (const QString &err : errors) {
                    addLogMessage("  " + err, "error");
                }
            } else {
                addLogMessage("Ошибок в логе OpenVPN не найдено", "success");
            }
            file.close();
        }
    } else {
        addLogMessage("Лог файл OpenVPN не найден: " + logFile2, "warning");
    }

    addLogMessage("Проверка сертификатов:", "info");

    if (QFile::exists(caCertPath)) {
        QString caInfo = executeCommand("openssl x509 -in " + caCertPath +
        " -noout -subject -issuer -dates 2>&1");
        addLogMessage("CA сертификат:\n" + caInfo, "info");
    } else {
        addLogMessage("CA сертификат не найден: " + caCertPath, "error");
    }

    if (QFile::exists(serverCertPath)) {
        QString certVerify = executeCommand("openssl verify -CAfile " + caCertPath + " " +
        serverCertPath + " 2>&1");
        addLogMessage("Проверка сертификата сервера: " + certVerify,
                      certVerify.contains("OK") ? "success" : "error");

        QString certInfo = executeCommand("openssl x509 -in " + serverCertPath +
        " -noout -subject -issuer -dates 2>&1");
        addLogMessage("Информация о сертификате сервера:\n" + certInfo, "info");
    } else {
        addLogMessage("Сертификат сервера не найден: " + serverCertPath, "error");
    }

    QString ovpnVer = executeCommand(openVPNExecutablePath + " --version | head -2");
    addLogMessage("Версия OpenVPN:\n" + ovpnVer, "info");

    if (QFile::exists(serverConfigPath)) {
        QFile cfgFile(serverConfigPath);
        if (cfgFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString cfgContent = cfgFile.readAll();
            cfgFile.close();

            QStringList lines = cfgContent.split('\n');
            QString firstLines;
            for (int i = 0; i < qMin(10, lines.size()); i++) {
                firstLines += lines[i] + "\n";
            }
            addLogMessage("Содержимое server.conf (первые 10 строк):\n" + firstLines, "info");

            if (cfgContent.contains("\r\n")) {
                addLogMessage("ВНИМАНИЕ: Файл содержит Windows-переносы строк (CRLF)", "warning");
            }
        }
    } else {
        addLogMessage("Конфигурационный файл не найден: " + serverConfigPath, "error");
    }

    if (openVPNServerProcess && openVPNServerProcess->state() == QProcess::Running) {
        addLogMessage("Процесс OpenVPN запущен, PID: " +
        QString::number(openVPNServerProcess->processId()), "success");
    } else {
        addLogMessage("Процесс OpenVPN не запущен", "warning");
    }

    verifyRouting();

    addLogMessage("Для проверки доступности извне выполните:", "info");
    addLogMessage("  telnet " + externalIP + " " + QString::number(spinServerPort->value()), "info");
    addLogMessage("  nmap -p " + QString::number(spinServerPort->value()) + " " + externalIP, "info");

    addLogMessage("=== КОНЕЦ ДИАГНОСТИКИ ===", "info");
}

void MainWindow::generateTestAndroidConfig()
{
    QString savePath = QFileDialog::getSaveFileName(this, "Сохранить тестовый конфиг для Android",
                                                    QDir::homePath() + "/android_test.ovpn",
                                                    "OpenVPN Config (*.ovpn)");
    if (savePath.isEmpty()) return;

    QString externalIP = executeCommand("curl -s ifconfig.me || curl -s icanhazip.com || echo '176.51.100.76'");
    externalIP = externalIP.trimmed();

    QString config;
    config += "# OpenVPN Android Test Configuration\n";
    config += "# Generated by Tor Manager\n";
    config += "# Server IP: " + externalIP + "\n";
    config += "# Date: " + QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") + "\n";
    config += "\n";

    config += "client\n";
    config += "dev tun\n";
    config += "proto tcp\n";
    config += "remote " + externalIP + " " + QString::number(spinServerPort->value()) + "\n";
    config += "resolv-retry infinite\n";
    config += "nobind\n";
    config += "persist-key\n";
    config += "persist-tun\n";
    config += "\n";

    config += "# Security Settings\n";
    config += "remote-cert-tls server\n";
    config += "cipher AES-256-CBC\n";
    config += "auth SHA256\n";
    config += "auth-nocache\n";
    config += "tls-version-min 1.2\n";
    config += "\n";

    if (QFile::exists(caCertPath)) {
        config += "<ca>\n";
        QFile caFile(caCertPath);
        if (caFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString caContent = caFile.readAll();
            caFile.close();

            if (!caContent.contains("BEGIN CERTIFICATE")) {
                addLogMessage("CA сертификат имеет неверный формат!", "error");
                config += "# ОШИБКА: Неверный формат сертификата\n";
            } else {
                config += caContent;
            }
        }
    } else {
        config += "# CA сертификат не найден\n";
    }
    config += "</ca>\n";
    config += "\n";

    config += "verb 3\n";
    config += "mute 10\n";

    QFile file(savePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        file.write(config.toUtf8());
        file.close();
        addLogMessage("Тестовый Android конфиг сохранен: " + savePath, "success");

        QMessageBox::information(this, "Тестовый конфиг создан",
                                 "Создан упрощенный конфигурационный файл для Android.\n\n"
                                 "Путь: " + savePath + "\n\n"
                                 "Инструкция:\n"
                                 "1. Скопируйте файл на Android устройство\n"
                                 "2. В OpenVPN для Android импортируйте этот файл\n"
                                 "3. Попробуйте подключиться\n\n"
                                 "Если подключение не работает, выполните диагностику на сервере.");
    } else {
        addLogMessage("Ошибка сохранения файла: " + savePath, "error");
        QMessageBox::critical(this, "Ошибка", "Не удалось сохранить файл конфигурации");
    }
}

void MainWindow::testServerConfig()
{
    if (!QFile::exists(serverConfigPath)) {
        QMessageBox::warning(this, "Ошибка", "Конфигурация сервера не найдена: " + serverConfigPath);
        return;
    }

    addLogMessage("Тестирование конфигурации сервера...", "info");

    QString command = openVPNExecutablePath + " --config \"" + serverConfigPath + "\" --test";
    addLogMessage("Команда: " + command, "info");

    QProcess testProcess;
    testProcess.start(openVPNExecutablePath, QStringList() << "--config" << serverConfigPath << "--test");

    if (testProcess.waitForFinished(10000)) {
        QString output = QString::fromUtf8(testProcess.readAllStandardOutput());
        QString error = QString::fromUtf8(testProcess.readAllStandardError());

        if (testProcess.exitCode() == 0) {
            addLogMessage("✓ Конфигурация успешно прошла проверку", "success");

            if (!output.isEmpty()) {
                addLogMessage("Вывод:\n" + output, "info");
            }

            QMessageBox::information(this, "Проверка конфигурации",
                                     "Конфигурация сервера валидна!\n\n"
                                     "Путь: " + serverConfigPath);
        } else {
            addLogMessage("✗ Ошибка в конфигурации", "error");
            addLogMessage("Код ошибки: " + QString::number(testProcess.exitCode()), "error");

            if (!error.isEmpty()) {
                addLogMessage("Сообщение об ошибке:\n" + error, "error");
            }

            if (!output.isEmpty()) {
                addLogMessage("Вывод:\n" + output, "info");
            }

            QString userMessage = "Ошибка проверки конфигурации:\n\n";

            if (error.contains("Unrecognized option")) {
                userMessage += "Неизвестная опция в конфигурационном файле.\n";
                userMessage += "Проверьте синтаксис на наличие лишних пробелов или символов.\n\n";

                QRegularExpression re("Unrecognized option or missing.*?:\\s+(\\w+)");
                QRegularExpressionMatch match = re.match(error);
                if (match.hasMatch()) {
                    userMessage += "Проблемная опция: " + match.captured(1) + "\n";
                }
            } else if (error.contains("no such file")) {
                userMessage += "Файл сертификата или ключа не найден.\n";
                userMessage += "Проверьте пути к файлам в конфигурации.\n";
            } else if (error.contains("permission denied")) {
                userMessage += "Нет прав доступа к файлам сертификатов.\n";
                userMessage += "Запустите: sudo chmod 644 " + certsDir + "/*\n";
            } else {
                userMessage += error;
            }

            QMessageBox::critical(this, "Ошибка конфигурации", userMessage);
        }
    } else {
        addLogMessage("Таймаут при проверке конфигурации", "error");
        QMessageBox::critical(this, "Ошибка", "Таймаут при проверке конфигурации");
    }
}

bool MainWindow::validateServerConfig()
{
    if (!QFile::exists(serverConfigPath)) {
        addLogMessage("Файл конфигурации не найден", "error");
        return false;
    }

    QFile file(serverConfigPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        addLogMessage("Не удалось прочитать файл конфигурации", "error");
        return false;
    }

    QString content = file.readAll();
    file.close();

    QStringList required = {"port", "proto", "dev", "ca", "cert", "key", "dh"};
    QStringList missing;

    for (const QString &opt : required) {
        if (!content.contains(QRegularExpression("^" + opt + "\\s",
            QRegularExpression::MultilineOption))) {
            missing << opt;
            }
    }

    if (!missing.isEmpty()) {
        addLogMessage("Отсутствуют обязательные опции: " + missing.join(", "), "error");
        return false;
    }

    QRegularExpression caRegex("^ca\\s+(.+)$", QRegularExpression::MultilineOption);
    QRegularExpressionMatch match = caRegex.match(content);
    if (match.hasMatch()) {
        QString caPath = match.captured(1).trimmed();
        if (!QFile::exists(caPath)) {
            addLogMessage("CA сертификат не найден по пути: " + caPath, "error");
            return false;
        }
    }

    QRegularExpression certRegex("^cert\\s+(.+)$", QRegularExpression::MultilineOption);
    match = certRegex.match(content);
    if (match.hasMatch()) {
        QString certPath = match.captured(1).trimmed();
        if (!QFile::exists(certPath)) {
            addLogMessage("Сертификат сервера не найден по пути: " + certPath, "error");
            return false;
        }
    }

    QRegularExpression keyRegex("^key\\s+(.+)$", QRegularExpression::MultilineOption);
    match = keyRegex.match(content);
    if (match.hasMatch()) {
        QString keyPath = match.captured(1).trimmed();
        if (!QFile::exists(keyPath)) {
            addLogMessage("Ключ сервера не найден по пути: " + keyPath, "error");
            return false;
        }
    }

    QRegularExpression dhRegex("^dh\\s+(.+)$", QRegularExpression::MultilineOption);
    match = dhRegex.match(content);
    if (match.hasMatch()) {
        QString dhPath = match.captured(1).trimmed();
        if (!QFile::exists(dhPath)) {
            addLogMessage("DH параметры не найдены по пути: " + dhPath, "error");
            return false;
        }
    }

    addLogMessage("Конфигурация сервера валидна", "success");
    return true;
}

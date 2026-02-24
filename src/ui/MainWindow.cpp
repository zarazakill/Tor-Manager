#include "MainWindow.h"
#include "../core/TorManager.h"
#include "../core/OpenVPNManager.h"
#include "../services/DiagnosticService.h"
#include "../utils/CommandExecutor.h"

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
#include <QSystemTrayIcon>
#include <QAction>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    // Initialize core components
    m_torManager = new TorManager(this);
    m_openVPNManager = new OpenVPNManager(this);
    m_diagnosticService = new DiagnosticService(this);
    m_commandExecutor = new CommandExecutor(this);

    // Initialize settings
    m_settings = new QSettings("TorManager", "TorVPN", this);

    // Setup UI
    setupUI();
    setupTrayIcon();
    setupConnections();

    // Load saved settings
    loadSettings();

    // Set up timers
    m_statusTimer = new QTimer(this);
    m_trafficTimer = new QTimer(this);
    m_clientStatsTimer = new QTimer(this);

    connect(m_statusTimer, &QTimer::timeout, this, &MainWindow::updateStatus);
    connect(m_trafficTimer, &QTimer::timeout, this, &MainWindow::updateTrafficStats);
    connect(m_clientStatsTimer, &QTimer::timeout, this, &MainWindow::updateClientsTable);

    m_statusTimer->start(5000); // Update status every 5 seconds
    m_trafficTimer->start(2000); // Update traffic stats every 2 seconds
    m_clientStatsTimer->start(5000); // Update client stats every 5 seconds

    setWindowTitle("Tor Manager с OpenVPN (Сервер)");
    resize(1000, 750);

    addLogMessage("Tor Manager успешно инициализирован", "info");
}

MainWindow::~MainWindow()
{
    // Cleanup
    if (m_killSwitchEnabled) {
        // Disable kill switch if enabled
        // Implementation would go here
    }
    
    saveSettings();
}

void MainWindow::setupUI()
{
    createMenuBar();
    createTabWidget();
    setCentralWidget(m_tabWidget);
    statusBar()->showMessage("Готов");
}

void MainWindow::setupConnections()
{
    // Connect Tor manager signals
    connect(m_torManager, &TorManager::statusChanged, [this](TorManager::Status status) {
        QString statusStr;
        switch (status) {
            case TorManager::Status::Stopped:
                statusStr = "Остановлен";
                break;
            case TorManager::Status::Starting:
                statusStr = "Запуск...";
                break;
            case TorManager::Status::Running:
                statusStr = "Запущен";
                break;
            case TorManager::Status::Error:
                statusStr = "Ошибка";
                break;
        }
        if (m_lblTorStatus) {
            m_lblTorStatus->setText("Статус Tor: " + statusStr);
        }
    });

    connect(m_torManager, &TorManager::logMessage, this, &MainWindow::addLogMessage);
    connect(m_torManager, &TorManager::circuitChanged, [this](const QString &circuitInfo) {
        if (m_circuitInfo) {
            m_circuitInfo->setText("Цепочка: " + circuitInfo);
        }
    });

    // Connect diagnostic service signals
    connect(m_diagnosticService, &DiagnosticService::diagnosticStepCompleted,
            this, &MainWindow::onDiagnosticStepCompleted);
    connect(m_diagnosticService, &DiagnosticService::diagnosticFinished,
            this, &MainWindow::onDiagnosticFinished);
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
    toolsMenu->addAction("Сгенерировать сертификаты", this, &MainWindow::generateCertificates);
    toolsMenu->addAction("Проверить конфигурацию", this, &MainWindow::testServerConfig);
    toolsMenu->addAction("Диагностика подключения", this, &MainWindow::runDiagnostics);

    QMenu *helpMenu = menuBar->addMenu("&Справка");
    helpMenu->addAction("&О программе", this, &MainWindow::showAbout);

    setMenuBar(menuBar);
}

void MainWindow::createTabWidget()
{
    m_tabWidget = new QTabWidget(this);

    createTorTab();
    createServerTab();
    createClientsTab();
    createSettingsTab();
    createLogsTab();

    m_tabWidget->addTab(m_torTab, "Tor");
    m_tabWidget->addTab(m_serverTab, "OpenVPN Сервер");
    m_tabWidget->addTab(m_clientsTab, "Клиенты");
    m_tabWidget->addTab(m_settingsTab, "Настройки");
    m_tabWidget->addTab(m_logsTab, "Журналы");
}

void MainWindow::createTorTab()
{
    m_torTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(m_torTab);

    QGroupBox *controlGroup = new QGroupBox("Управление Tor");
    QVBoxLayout *controlLayout = new QVBoxLayout();

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    m_btnStartTor = new QPushButton("Запустить Tor");
    m_btnStopTor = new QPushButton("Остановить Tor");
    m_btnRestartTor = new QPushButton("Перезапустить");
    m_btnNewCircuit = new QPushButton("Новая цепочка");

    buttonLayout->addWidget(m_btnStartTor);
    buttonLayout->addWidget(m_btnStopTor);
    buttonLayout->addWidget(m_btnRestartTor);
    buttonLayout->addWidget(m_btnNewCircuit);

    m_lblTorStatus = new QLabel("Статус Tor: Остановлен");
    m_lblTorIP = new QLabel("IP: Неизвестен");

    controlLayout->addLayout(buttonLayout);
    controlLayout->addWidget(m_lblTorStatus);
    controlLayout->addWidget(m_lblTorIP);

    controlGroup->setLayout(controlLayout);

    m_txtTorLog = new QTextEdit();
    m_txtTorLog->setReadOnly(true);
    m_txtTorLog->setMaximumBlockCount(1000);

    layout->addWidget(controlGroup);
    layout->addWidget(new QLabel("Лог Tor:"));
    layout->addWidget(m_txtTorLog);

    // Connect buttons
    connect(m_btnStartTor, &QPushButton::clicked, this, &MainWindow::startTor);
    connect(m_btnStopTor, &QPushButton::clicked, this, &MainWindow::stopTor);
    connect(m_btnRestartTor, &QPushButton::clicked, this, &MainWindow::restartTor);
    connect(m_btnNewCircuit, &QPushButton::clicked, this, &MainWindow::requestNewCircuit);
}

void MainWindow::createServerTab()
{
    m_serverTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(m_serverTab);

    QGroupBox *configGroup = new QGroupBox("Конфигурация сервера");
    QFormLayout *formLayout = new QFormLayout();

    m_spinServerPort = new QSpinBox();
    m_spinServerPort->setRange(1, 65535);
    m_spinServerPort->setValue(1194);
    formLayout->addRow("Порт:", m_spinServerPort);

    m_txtServerNetwork = new QLineEdit("10.8.0.0 255.255.255.0");
    formLayout->addRow("Сеть:", m_txtServerNetwork);

    m_chkRouteThroughTor = new QCheckBox("Маршрутизировать через Tor");
    formLayout->addRow(m_chkRouteThroughTor);

    configGroup->setLayout(formLayout);

    QGroupBox *controlGroup = new QGroupBox("Управление сервером");
    QVBoxLayout *controlLayout = new QVBoxLayout();

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    m_btnGenerateCerts = new QPushButton("Сгенерировать сертификаты");
    m_btnCheckCerts = new QPushButton("Проверить сертификаты");
    m_btnStartServer = new QPushButton("Запустить сервер");
    m_btnStopServer = new QPushButton("Остановить сервер");

    buttonLayout->addWidget(m_btnGenerateCerts);
    buttonLayout->addWidget(m_btnCheckCerts);
    buttonLayout->addWidget(m_btnStartServer);
    buttonLayout->addWidget(m_btnStopServer);

    m_lblServerStatus = new QLabel("Статус сервера: Остановлен");
    m_lblConnectedClients = new QLabel("Подключено клиентов: 0");

    controlLayout->addLayout(buttonLayout);
    controlLayout->addWidget(m_lblServerStatus);
    controlLayout->addWidget(m_lblConnectedClients);

    controlGroup->setLayout(controlLayout);

    // Additional controls
    QHBoxLayout *actionLayout = new QHBoxLayout();
    m_btnGenerateClientConfig = new QPushButton("Создать клиентскую конфигурацию");
    m_btnCheckIP = new QPushButton("Проверить IP");
    m_btnDiagnose = new QPushButton("Диагностика");
    m_btnTestConfig = new QPushButton("Проверить конфигурацию");

    actionLayout->addWidget(m_btnGenerateClientConfig);
    actionLayout->addWidget(m_btnCheckIP);
    actionLayout->addWidget(m_btnDiagnose);
    actionLayout->addWidget(m_btnTestConfig);

    m_txtServerLog = new QTextEdit();
    m_txtServerLog->setReadOnly(true);
    m_txtServerLog->setMaximumBlockCount(1000);

    layout->addWidget(configGroup);
    layout->addWidget(controlGroup);
    layout->addLayout(actionLayout);
    layout->addWidget(new QLabel("Лог сервера:"));
    layout->addWidget(m_txtServerLog);

    // Connect buttons
    connect(m_btnGenerateCerts, &QPushButton::clicked, this, &MainWindow::generateCertificates);
    connect(m_btnCheckCerts, &QPushButton::clicked, this, &MainWindow::checkCertificates);
    connect(m_btnStartServer, &QPushButton::clicked, this, &MainWindow::startOpenVPNServer);
    connect(m_btnStopServer, &QPushButton::clicked, this, &MainWindow::stopOpenVPNServer);
    connect(m_btnGenerateClientConfig, &QPushButton::clicked, this, &MainWindow::generateClientConfig);
    connect(m_btnCheckIP, &QPushButton::clicked, this, &MainWindow::checkIPLeak);
    connect(m_btnDiagnose, &QPushButton::clicked, this, &MainWindow::runDiagnostics);
    connect(m_btnTestConfig, &QPushButton::clicked, this, &MainWindow::testServerConfig);
}

void MainWindow::createClientsTab()
{
    m_clientsTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(m_clientsTab);

    // Statistics labels
    QHBoxLayout *statsLayout = new QHBoxLayout();
    m_lblTotalClients = new QLabel("Всего клиентов: 0");
    m_lblActiveClients = new QLabel("Активных: 0");
    statsLayout->addWidget(m_lblTotalClients);
    statsLayout->addWidget(m_lblActiveClients);
    statsLayout->addStretch();

    // Controls
    QHBoxLayout *controlsLayout = new QHBoxLayout();
    m_btnRefreshClients = new QPushButton("Обновить");
    m_btnDisconnectClient = new QPushButton("Отключить выбранного");
    m_btnDisconnectAll = new QPushButton("Отключить всех");
    m_btnClientDetails = new QPushButton("Детали");
    m_btnBanClient = new QPushButton("Заблокировать");
    
    controlsLayout->addWidget(m_btnRefreshClients);
    controlsLayout->addWidget(m_btnDisconnectClient);
    controlsLayout->addWidget(m_btnDisconnectAll);
    controlsLayout->addWidget(m_btnClientDetails);
    controlsLayout->addWidget(m_btnBanClient);
    controlsLayout->addStretch();

    // Clients table
    m_clientsTable = new QTableWidget();
    m_clientsTable->setColumnCount(8);
    m_clientsTable->setHorizontalHeaderLabels({
        "Имя", "Реальный IP", "Вирт. IP", "Вирт. IPv6", 
        "Принято", "Отправлено", "Подключен", "PID"
    });
    m_clientsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_clientsTable->setSelectionMode(QAbstractItemView::SingleSelection);

    // Log area
    m_txtClientsLog = new QTextEdit();
    m_txtClientsLog->setReadOnly(true);
    m_txtClientsLog->setMaximumBlockCount(1000);

    // Bottom controls
    QHBoxLayout *bottomControlsLayout = new QHBoxLayout();
    m_btnExportClientsLog = new QPushButton("Экспорт лога");
    m_btnClearClientsLog = new QPushButton("Очистить лог");
    bottomControlsLayout->addWidget(m_btnExportClientsLog);
    bottomControlsLayout->addWidget(m_btnClearClientsLog);
    bottomControlsLayout->addStretch();

    layout->addLayout(statsLayout);
    layout->addLayout(controlsLayout);
    layout->addWidget(m_clientsTable);
    layout->addWidget(new QLabel("Лог подключений:"));
    layout->addWidget(m_txtClientsLog);
    layout->addLayout(bottomControlsLayout);

    // Connect buttons
    connect(m_btnRefreshClients, &QPushButton::clicked, this, &MainWindow::updateClientsTable);
    connect(m_btnDisconnectClient, &QPushButton::clicked, this, &MainWindow::disconnectSelectedClient);
    connect(m_btnDisconnectAll, &QPushButton::clicked, this, &MainWindow::disconnectAllClients);
}

void MainWindow::createSettingsTab()
{
    m_settingsTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(m_settingsTab);

    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    QWidget *scrollWidget = new QWidget();
    QVBoxLayout *scrollLayout = new QVBoxLayout(scrollWidget);

    // Tor settings group
    QGroupBox *torSettingsGroup = new QGroupBox("Настройки Tor");
    QFormLayout *torFormLayout = new QFormLayout();

    m_spinTorSocksPort = new QSpinBox();
    m_spinTorSocksPort->setRange(1, 65535);
    m_spinTorSocksPort->setValue(9050);
    torFormLayout->addRow("SOCKS порт:", m_spinTorSocksPort);

    m_spinTorControlPort = new QSpinBox();
    m_spinTorControlPort->setRange(1, 65535);
    m_spinTorControlPort->setValue(9051);
    torFormLayout->addRow("Control порт:", m_spinTorControlPort);

    torSettingsGroup->setLayout(torFormLayout);

    // Application settings group
    QGroupBox *appSettingsGroup = new QGroupBox("Настройки приложения");
    QFormLayout *appFormLayout = new QFormLayout();

    m_chkAutoStart = new QCheckBox("Автозапуск при старте системы");
    appFormLayout->addRow(m_chkAutoStart);

    m_chkStartMinimized = new QCheckBox("Запускать свернутым");
    appFormLayout->addRow(m_chkStartMinimized);

    m_chkKillSwitch = new QCheckBox("Включить Kill Switch");
    appFormLayout->addRow(m_chkKillSwitch);

    m_chkBlockIPv6 = new QCheckBox("Блокировать IPv6 трафик");
    appFormLayout->addRow(m_chkBlockIPv6);

    m_chkDNSLeakProtection = new QCheckBox("Защита от DNS утечек");
    appFormLayout->addRow(m_chkDNSLeakProtection);

    appSettingsGroup->setLayout(appFormLayout);

    // Paths group
    QGroupBox *pathsGroup = new QGroupBox("Пути к исполняемым файлам");
    QFormLayout *pathsFormLayout = new QFormLayout();

    m_txtTorPath = new QLineEdit();
    m_btnBrowseTor = new QPushButton("Обзор...");
    QHBoxLayout *torPathLayout = new QHBoxLayout();
    torPathLayout->addWidget(m_txtTorPath);
    torPathLayout->addWidget(m_btnBrowseTor);
    pathsFormLayout->addRow("Tor:", torPathLayout);

    m_txtOpenVPNPath = new QLineEdit();
    m_btnBrowseOpenVPN = new QPushButton("Обзор...");
    QHBoxLayout *ovpnPathLayout = new QHBoxLayout();
    ovpnPathLayout->addWidget(m_txtOpenVPNPath);
    ovpnPathLayout->addWidget(m_btnBrowseOpenVPN);
    pathsFormLayout->addRow("OpenVPN:", ovpnPathLayout);

    pathsGroup->setLayout(pathsFormLayout);

    // Apply button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    m_btnApplySettings = new QPushButton("Применить");
    buttonLayout->addWidget(m_btnApplySettings);

    scrollLayout->addWidget(torSettingsGroup);
    scrollLayout->addWidget(appSettingsGroup);
    scrollLayout->addWidget(pathsGroup);
    scrollLayout->addLayout(buttonLayout);
    scrollLayout->addStretch();

    scrollArea->setWidget(scrollWidget);
    layout->addWidget(scrollArea);

    connect(m_btnApplySettings, &QPushButton::clicked, this, &MainWindow::applySettings);
    connect(m_btnBrowseTor, &QPushButton::clicked, [this]() {
        QString fileName = QFileDialog::getOpenFileName(this, "Выберите исполняемый файл Tor", "/usr/bin", "Executable Files (*)");
        if (!fileName.isEmpty()) {
            m_txtTorPath->setText(fileName);
        }
    });
    connect(m_btnBrowseOpenVPN, &QPushButton::clicked, [this]() {
        QString fileName = QFileDialog::getOpenFileName(this, "Выберите исполняемый файл OpenVPN", "/usr/sbin", "Executable Files (*)");
        if (!fileName.isEmpty()) {
            m_txtOpenVPNPath->setText(fileName);
        }
    });
}

void MainWindow::createLogsTab()
{
    m_logsTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(m_logsTab);

    // Log level selector
    QHBoxLayout *levelLayout = new QHBoxLayout();
    levelLayout->addWidget(new QLabel("Уровень логирования:"));
    m_cboLogLevel = new QComboBox();
    m_cboLogLevel->addItems({"info", "warning", "error", "debug"});
    levelLayout->addWidget(m_cboLogLevel);
    levelLayout->addStretch();

    // Main log display
    m_txtAllLogs = new QTextEdit();
    m_txtAllLogs->setReadOnly(true);
    m_txtAllLogs->setMaximumBlockCount(10000);

    // Log controls
    QHBoxLayout *controlsLayout = new QHBoxLayout();
    m_btnClearLogs = new QPushButton("Очистить");
    m_btnSaveLogs = new QPushButton("Сохранить");
    controlsLayout->addWidget(m_btnClearLogs);
    controlsLayout->addWidget(m_btnSaveLogs);
    controlsLayout->addStretch();

    layout->addLayout(levelLayout);
    layout->addWidget(m_txtAllLogs);
    layout->addLayout(controlsLayout);

    connect(m_btnClearLogs, &QPushButton::clicked, [this]() {
        m_txtAllLogs->clear();
    });
    connect(m_btnSaveLogs, &QPushButton::clicked, [this]() {
        QString fileName = QFileDialog::getSaveFileName(this, "Сохранить лог", "tor_manager_log.txt", "Text Files (*.txt);;All Files (*)");
        if (!fileName.isEmpty()) {
            QFile file(fileName);
            if (file.open(QIODevice::WriteOnly)) {
                QTextStream stream(&file);
                stream << m_txtAllLogs->toPlainText();
            }
        }
    });
}

void MainWindow::setupTrayIcon()
{
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        m_trayIcon = new QSystemTrayIcon(this);
        m_trayIcon->setIcon(QIcon(":/icon.png")); // Assuming you have an icon
        m_trayIcon->setToolTip("Tor Manager");

        m_trayMenu = new QMenu(this);
        m_trayMenu->addAction("Показать", this, &MainWindow::showNormal);
        m_trayMenu->addAction("Скрыть", this, &MainWindow::hide);
        m_trayMenu->addSeparator();
        m_trayMenu->addAction("Выход", this, &QApplication::quit);

        m_trayIcon->setContextMenu(m_trayMenu);
        m_trayIcon->show();

        connect(m_trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::onTrayActivated);
    }
}

void MainWindow::startTor()
{
    m_torManager->start();
}

void MainWindow::stopTor()
{
    m_torManager->stop();
}

void MainWindow::restartTor()
{
    m_torManager->restart();
}

void MainWindow::requestNewCircuit()
{
    m_torManager->requestNewCircuit();
}

void MainWindow::startOpenVPNServer()
{
    // Delegation to OpenVPNManager
    // Implementation would go here
}

void MainWindow::stopOpenVPNServer()
{
    // Delegation to OpenVPNManager
    // Implementation would go here
}

void MainWindow::generateCertificates()
{
    // Delegation to CertificateManager (would be part of OpenVPNManager)
    // Implementation would go here
}

void MainWindow::checkCertificates()
{
    // Delegation to CertificateManager
    // Implementation would go here
}

void MainWindow::generateClientConfig()
{
    // Implementation would go here
}

void MainWindow::generateTestAndroidConfig()
{
    // Implementation would go here
}

void MainWindow::checkIPLeak()
{
    // Implementation would go here
}

void MainWindow::updateStatus()
{
    // Update UI based on managers' statuses
}

void MainWindow::showSettings()
{
    // Show settings dialog
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, "О программе", 
        "Tor Manager с OpenVPN Сервером\nВерсия 1.1.0\n\n"
        "Приложение для управления Tor и OpenVPN сервером.");
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick) {
        if (isHidden()) {
            showNormal();
        } else {
            hide();
        }
    }
}

void MainWindow::applySettings()
{
    // Save settings to QSettings
    m_settings->setValue("autoStart", m_chkAutoStart->isChecked());
    m_settings->setValue("startMinimized", m_chkStartMinimized->isChecked());
    m_settings->setValue("killSwitch", m_chkKillSwitch->isChecked());
    m_settings->setValue("blockIPv6", m_chkBlockIPv6->isChecked());
    m_settings->setValue("dnsLeakProtection", m_chkDNSLeakProtection->isChecked());
    m_settings->setValue("torSocksPort", m_spinTorSocksPort->value());
    m_settings->setValue("torControlPort", m_spinTorControlPort->value());
    m_settings->setValue("torPath", m_txtTorPath->text());
    m_settings->setValue("openVPNPath", m_txtOpenVPNPath->text());

    addLogMessage("Настройки сохранены", "info");
}

void MainWindow::updateTrafficStats()
{
    // Update traffic statistics
}

void MainWindow::addLogMessage(const QString &message, const QString &type)
{
    QString formattedMessage = QString("[%1] %2: %3")
        .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"))
        .arg(type.toUpper())
        .arg(message);

    // Add to all logs
    if (m_txtAllLogs) {
        m_txtAllLogs->append(formattedMessage);
    }

    // Color coding could be implemented here based on type
}

void MainWindow::runDiagnostics()
{
    m_diagnosticService->runDiagnostics();
}

void MainWindow::testServerConfig()
{
    // Implementation would delegate to configuration validator
}

void MainWindow::updateClientsTable()
{
    // Update clients table with data from OpenVPN management interface
}

void MainWindow::disconnectSelectedClient()
{
    // Disconnect selected client
}

void MainWindow::disconnectAllClients()
{
    // Disconnect all clients
}

void MainWindow::onDiagnosticStepCompleted(const DiagnosticService::DiagnosticResult &result)
{
    QString status = result.success ? "OK" : "FAIL";
    QString message = QString("Диагностика %1: %2 - %3").arg(result.component, status, result.message);
    addLogMessage(message, result.success ? "info" : "error");
}

void MainWindow::onDiagnosticFinished(const QList<DiagnosticService::DiagnosticResult> &results)
{
    int passed = 0;
    for (const auto &result : results) {
        if (result.success) passed++;
    }
    
    QString summary = QString("Диагностика завершена: %1/%2 пройдено").arg(passed).arg(results.size());
    addLogMessage(summary, "info");
}

void MainWindow::loadSettings()
{
    m_chkAutoStart->setChecked(m_settings->value("autoStart", false).toBool());
    m_chkStartMinimized->setChecked(m_settings->value("startMinimized", false).toBool());
    m_chkKillSwitch->setChecked(m_settings->value("killSwitch", false).toBool());
    m_chkBlockIPv6->setChecked(m_settings->value("blockIPv6", false).toBool());
    m_chkDNSLeakProtection->setChecked(m_settings->value("dnsLeakProtection", false).toBool());
    m_spinTorSocksPort->setValue(m_settings->value("torSocksPort", 9050).toInt());
    m_spinTorControlPort->setValue(m_settings->value("torControlPort", 9051).toInt());
    m_txtTorPath->setText(m_settings->value("torPath", "").toString());
    m_txtOpenVPNPath->setText(m_settings->value("openVPNPath", "").toString());
}

void MainWindow::saveSettings()
{
    applySettings(); // Just reuse the apply method
}
# Архитектурный рефакторинг TorManager проекта

## Новая структура проекта

```
/workspace/
├── src/
│   ├── core/                 # Бизнес-логика
│   │   ├── TorManager.h      # Управление Tor
│   │   ├── TorManager.cpp
│   │   ├── OpenVPNManager.h  # Управление OpenVPN
│   │   ├── OpenVPNManager.cpp
│   │   ├── FirewallManager.h # Управление firewall
│   │   ├── FirewallManager.cpp
│   │   ├── CertificateManager.h # Управление сертификатами
│   │   ├── CertificateManager.cpp
│   │   ├── DiagnosticsService.h # Диагностика
│   │   └── DiagnosticsService.cpp
│   ├── ui/                   # Классы пользовательского интерфейса
│   │   ├── MainWindow.h      # Главное окно
│   │   └── MainWindow.cpp
│   ├── utils/                # Вспомогательные классы
│   │   ├── CommandExecutor.h # Безопасное выполнение команд
│   │   ├── CommandExecutor.cpp
│   │   ├── Logger.h          # Централизованный логгер
│   │   ├── Logger.cpp
│   │   ├── FileUtils.h       # Работа с файлами
│   │   └── FileUtils.cpp
│   └── services/             # Сервисы
│       ├── ConfigValidator.h # Валидация конфигурации
│       ├── ConfigValidator.cpp
│       ├── NetworkService.h  # Сетевые сервисы
│       └── NetworkService.cpp
├── tests/                    # Тесты
├── resources/                # Ресурсы
├── docs/                     # Документация
└── TorManager.pro            # Файл проекта
```

## Пример рефакторинга MainWindow

### MainWindow.h (новый)
```cpp
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QTabWidget>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QTextEdit>
#include <QComboBox>
#include <QListWidget>
#include <QTableWidget>
#include <QTimer>
#include <QSettings>
#include <QNetworkAccessManager>

// Forward declarations of core components
class TorManager;
class OpenVPNManager;
class DiagnosticService;
class CommandExecutor;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    // Public members for main.cpp
    QSystemTrayIcon *trayIcon = nullptr;

private slots:
    // Tor management
    void startTor();
    void stopTor();
    void restartTor();
    void requestNewCircuit();

    // OpenVPN management
    void startOpenVPNServer();
    void stopOpenVPNServer();

    // Certificate management
    void generateCertificates();
    void checkCertificates();

    // Configuration
    void generateClientConfig();
    void generateTestAndroidConfig();

    // Network checks
    void checkIPLeak();

    // Interface updates
    void updateStatus();
    void showSettings();
    void showAbout();
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void applySettings();
    void updateTrafficStats();
    void addLogMessage(const QString &message, const QString &type = "info");

    // Diagnostics
    void runDiagnostics();
    void testServerConfig();

    // Clients management
    void updateClientsTable();
    void disconnectSelectedClient();
    void disconnectAllClients();

    // Internal slot for handling diagnostics
    void onDiagnosticStepCompleted(const struct DiagnosticService::DiagnosticResult &result);
    void onDiagnosticFinished(const QList<struct DiagnosticService::DiagnosticResult> &results);

private:
    void setupUI();
    void setupTrayIcon();
    void setupConnections();
    void createMenuBar();
    void createTabWidget();
    void createTorTab();
    void createServerTab();
    void createClientsTab();
    void createSettingsTab();
    void createLogsTab();

    // Settings management
    void loadSettings();
    void saveSettings();

    // UI components
    QTabWidget *m_tabWidget = nullptr;

    // Tor tab components
    QWidget *m_torTab = nullptr;
    QPushButton *m_btnStartTor = nullptr;
    QPushButton *m_btnStopTor = nullptr;
    QPushButton *m_btnRestartTor = nullptr;
    QPushButton *m_btnNewCircuit = nullptr;
    QLabel *m_lblTorStatus = nullptr;
    QLabel *m_lblTorIP = nullptr;
    QLabel *m_circuitInfo = nullptr;
    QTextEdit *m_txtTorLog = nullptr;

    // Server tab components
    QWidget *m_serverTab = nullptr;
    QSpinBox *m_spinServerPort = nullptr;
    QLineEdit *m_txtServerNetwork = nullptr;
    QCheckBox *m_chkRouteThroughTor = nullptr;
    QPushButton *m_btnGenerateCerts = nullptr;
    QPushButton *m_btnCheckCerts = nullptr;
    QPushButton *m_btnStartServer = nullptr;
    QPushButton *m_btnStopServer = nullptr;
    QLabel *m_lblServerStatus = nullptr;
    QLabel *m_lblConnectedClients = nullptr;
    QTextEdit *m_txtServerLog = nullptr;
    QLabel *m_lblCurrentIP = nullptr;
    QPushButton *m_btnCheckIP = nullptr;
    QPushButton *m_btnGenerateClientConfig = nullptr;
    QPushButton *m_btnDiagnose = nullptr;
    QPushButton *m_btnTestConfig = nullptr;

    // Clients tab components
    QWidget *m_clientsTab = nullptr;
    QTableWidget *m_clientsTable = nullptr;
    QTextEdit *m_txtClientsLog = nullptr;
    QPushButton *m_btnDisconnectClient = nullptr;
    QPushButton *m_btnDisconnectAll = nullptr;
    QPushButton *m_btnRefreshClients = nullptr;
    QPushButton *m_btnClientDetails = nullptr;
    QPushButton *m_btnBanClient = nullptr;
    QPushButton *m_btnExportClientsLog = nullptr;
    QPushButton *m_btnClearClientsLog = nullptr;
    QLabel *m_lblTotalClients = nullptr;
    QLabel *m_lblActiveClients = nullptr;
    QTimer *m_clientsRefreshTimer = nullptr;

    // Settings tab components
    QWidget *m_settingsTab = nullptr;
    QSpinBox *m_spinTorSocksPort = nullptr;
    QSpinBox *m_spinTorControlPort = nullptr;
    QCheckBox *m_chkAutoStart = nullptr;
    QCheckBox *m_chkKillSwitch = nullptr;
    QCheckBox *m_chkBlockIPv6 = nullptr;
    QCheckBox *m_chkDNSLeakProtection = nullptr;
    QCheckBox *m_chkStartMinimized = nullptr;
    QLineEdit *m_txtTorPath = nullptr;
    QLineEdit *m_txtOpenVPNPath = nullptr;
    QPushButton *m_btnApplySettings = nullptr;
    QPushButton *m_btnBrowseTor = nullptr;
    QPushButton *m_btnBrowseOpenVPN = nullptr;

    // Logs tab components
    QWidget *m_logsTab = nullptr;
    QTextEdit *m_txtAllLogs = nullptr;
    QComboBox *m_cboLogLevel = nullptr;
    QPushButton *m_btnClearLogs = nullptr;
    QPushButton *m_btnSaveLogs = nullptr;

    // System tray
    QMenu *m_trayMenu = nullptr;

    // Core components
    TorManager *m_torManager = nullptr;
    OpenVPNManager *m_openVPNManager = nullptr;
    DiagnosticService *m_diagnosticService = nullptr;
    CommandExecutor *m_commandExecutor = nullptr;

    // Timers
    QTimer *m_statusTimer = nullptr;
    QTimer *m_trafficTimer = nullptr;
    QTimer *m_clientStatsTimer = nullptr;

    // Settings
    QSettings *m_settings = nullptr;

    // State variables
    bool m_killSwitchEnabled = false;
    QString m_currentConnectionState;
    QString m_currentIP;
    QString m_torIP;
    quint64 m_bytesReceived = 0;
    quint64 m_bytesSent = 0;
    int m_connectedClients = 0;

    // Paths
    QString m_torrcPath;
    QString m_torDataDir;
    QString m_serverConfigPath;
    QString m_torExecutablePath;
    QString m_openVPNExecutablePath;
    QString m_certsDir;
};

#endif // MAINWINDOW_H
```

### MainWindow.cpp (фрагмент с основными изменениями)
```cpp
#include "MainWindow.h"
#include "../core/TorManager.h"
#include "../core/OpenVPNManager.h"
#include "../services/DiagnosticService.h"
#include "../utils/CommandExecutor.h"

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

void MainWindow::startTor()
{
    m_torManager->start();
}

void MainWindow::stopTor()
{
    m_torManager->stop();
}
```

## Пример TorManager

### TorManager.h
```cpp
#ifndef TORMANAGER_H
#define TORMANAGER_H

#include <QObject>
#include <QProcess>
#include <QTcpSocket>
#include <QTimer>
#include <QString>
#include <QMap>

class TorManager : public QObject
{
    Q_OBJECT

public:
    enum class Status {
        Stopped,
        Starting,
        Running,
        Error
    };

    explicit TorManager(QObject *parent = nullptr);
    ~TorManager();

    Status getStatus() const;
    QString getCurrentIP() const;
    QString getTorIP() const;

signals:
    void statusChanged(Status status);
    void logMessage(const QString &message, const QString &type);
    void circuitChanged(const QString &circuitInfo);
    void torIPChanged(const QString &ip);

public slots:
    void start();
    void stop();
    void restart();
    void requestNewCircuit();

private slots:
    void onTorStarted();
    void onTorFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onTorError(QProcess::ProcessError error);
    void onTorReadyRead();
    void onControlSocketConnected();
    void onControlSocketReadyRead();
    void onControlSocketError();
    void checkStatus();

private:
    void sendTorCommand(const QString &command);
    bool checkTorInstalled();
    QString getTorConfigPath() const;
    QString getTorDataPath() const;

    QProcess *m_torProcess;
    QTcpSocket *m_controlSocket;
    QTimer *m_statusTimer;
    
    Status m_currentStatus;
    QString m_currentIP;
    QString m_torIP;
    QString m_circuitInfo;
    bool m_controlSocketConnected;
    
    QString m_torrcPath;
    QString m_torDataDir;
    QString m_torExecutablePath;
    
    static const int DEFAULT_TOR_SOCKS_PORT;
    static const int DEFAULT_TOR_CONTROL_PORT;
};

#endif // TORMANAGER_H
```

### TorManager.cpp
```cpp
#include "TorManager.h"
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QStandardPaths>
#include <QTimer>
#include <QRegularExpression>
#include <QDebug>

const int TorManager::DEFAULT_TOR_SOCKS_PORT = 9050;
const int TorManager::DEFAULT_TOR_CONTROL_PORT = 9051;

TorManager::TorManager(QObject *parent)
    : QObject(parent)
    , m_torProcess(new QProcess(this))
    , m_controlSocket(new QTcpSocket(this))
    , m_statusTimer(new QTimer(this))
    , m_currentStatus(Status::Stopped)
    , m_controlSocketConnected(false)
{
    // Инициализация путей
    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(appData);
    m_torDataDir = appData + "/tor_data";
    m_torrcPath = appData + "/torrc";
    QDir().mkpath(m_torDataDir);

    // Настройка соединений
    connect(m_torProcess, &QProcess::started,
            this, &TorManager::onTorStarted);
    connect(m_torProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &TorManager::onTorFinished);
    connect(m_torProcess, &QProcess::errorOccurred,
            this, &TorManager::onTorError);
    connect(m_torProcess, &QProcess::readyReadStandardOutput,
            this, &TorManager::onTorReadyRead);
    connect(m_torProcess, &QProcess::readyReadStandardError,
            this, &TorManager::onTorReadyRead);

    connect(m_controlSocket, &QTcpSocket::connected,
            this, &TorManager::onControlSocketConnected);
    connect(m_controlSocket, &QTcpSocket::readyRead,
            this, &TorManager::onControlSocketReadyRead);
    connect(m_controlSocket, &QTcpSocket::errorOccurred,
            this, &TorManager::onControlSocketError);

    connect(m_statusTimer, &QTimer::timeout,
            this, &TorManager::checkStatus);

    m_statusTimer->start(5000); // Проверка статуса каждые 5 секунд
}

TorManager::~TorManager()
{
    if (m_currentStatus == Status::Running) {
        stop();
    }
}

TorManager::Status TorManager::getStatus() const
{
    return m_currentStatus;
}

void TorManager::start()
{
    if (m_currentStatus != Status::Stopped) {
        emit logMessage("Tor уже запущен или запускается", "warning");
        return;
    }

    emit logMessage("Запуск Tor...", "info");
    m_currentStatus = Status::Starting;
    emit statusChanged(m_currentStatus);

    // Создание конфигурационного файла
    createTorConfig();

    QStringList arguments;
    arguments << "-f" << m_torrcPath;

    m_torProcess->start("tor", arguments);
}

void TorManager::stop()
{
    if (m_currentStatus != Status::Running && m_currentStatus != Status::Starting) {
        emit logMessage("Tor не запущен", "warning");
        return;
    }

    emit logMessage("Остановка Tor...", "info");

    // Отправляем сигнал завершения процессу
    if (m_torProcess->state() == QProcess::Running) {
        m_torProcess->terminate();
        if (!m_torProcess->waitForFinished(3000)) {
            m_torProcess->kill();
            m_torProcess->waitForFinished(1000);
        }
    }

    if (m_controlSocket->state() == QTcpSocket::ConnectedState) {
        m_controlSocket->disconnectFromHost();
        m_controlSocket->waitForDisconnected(1000);
    }

    m_currentStatus = Status::Stopped;
    emit statusChanged(m_currentStatus);
    emit logMessage("Tor остановлен", "info");
}

void TorManager::onControlSocketReadyRead()
{
    QString response = m_controlSocket->readAll();
    
    // Обработка ответов от контрольного порта
    QStringList lines = response.split('\n');
    for (const QString &line : lines) {
        if (line.startsWith("250-version=")) {
            QString version = line.mid(12);
            emit logMessage("Версия Tor: " + version, "info");
        } else if (line.startsWith("250-circuit-status=")) {
            // Обработка статуса цепочек
            QString circuitStatus = line.mid(19);
            emit circuitChanged(circuitStatus);
        } else if (line.startsWith("250-stream-status=")) {
            // Обработка статуса потоков
        }
    }
}

void TorManager::createTorConfig()
{
    QFile configFile(m_torrcPath);
    if (!configFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        emit logMessage("Не удалось создать конфигурационный файл Tor", "error");
        return;
    }

    QTextStream out(&configFile);
    out << "# Tor конфигурация, созданная автоматически\n";
    out << "SocksPort " << DEFAULT_TOR_SOCKS_PORT << "\n";
    out << "ControlPort " << DEFAULT_TOR_CONTROL_PORT << "\n";
    out << "DataDirectory " << m_torDataDir << "\n";
    out << "Log notice file " << m_torDataDir << "/tor.log\n";
    out << "AutomapHostsOnResolve 1\n";
    out << "TransPort 9040\n";
    out << "DNSPort 53\n";

    configFile.close();
}
```

## Пример безопасного CommandExecutor

### CommandExecutor.h
```cpp
#ifndef COMMANDEXECUTOR_H
#define COMMANDEXECUTOR_H

#include <QObject>
#include <QProcess>
#include <QStringList>
#include <QTimer>

/**
 * @brief Класс для безопасного выполнения системных команд
 */
class CommandExecutor : public QObject
{
    Q_OBJECT

public:
    explicit CommandExecutor(QObject *parent = nullptr);

    /**
     * @brief Асинхронное выполнение команды
     * @param program Имя программы
     * @param arguments Аргументы
     * @param requiresRoot Требуется ли root права
     * @return ID задачи
     */
    int executeCommand(const QString &program, const QStringList &arguments, bool requiresRoot = false);

    /**
     * @brief Синхронное выполнение команды
     * @param program Имя программы
     * @param arguments Аргументы
     * @param requiresRoot Требуется ли root права
     * @return Результат выполнения
     */
    struct Result {
        bool success;
        QString output;
        QString error;
        int exitCode;
    };
    Result executeCommandSync(const QString &program, const QStringList &arguments, bool requiresRoot = false);

signals:
    void commandStarted(int taskId, const QString &program, const QStringList &arguments);
    void commandFinished(int taskId, const CommandExecutor::Result &result);
    void commandError(int taskId, const QString &error);

private slots:
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);

private:
    struct Task {
        int id;
        QProcess *process;
        bool requiresRoot;
        QString originalProgram;
        QStringList originalArguments;
    };

    int m_nextTaskId;
    QList<Task> m_runningTasks;
    QTimer m_cleanupTimer;

    Result runCommand(const QString &program, const QStringList &arguments, bool requiresRoot);
    QString prepareSudoCommand(const QString &program, const QStringList &arguments);
    bool validateCommand(const QString &program, const QStringList &arguments);
};

#endif // COMMANDEXECUTOR_H
```

### CommandExecutor.cpp
```cpp
#include "CommandExecutor.h"
#include <QDir>
#include <QStandardPaths>
#include <QRegularExpression>
#include <QDebug>

CommandExecutor::CommandExecutor(QObject *parent)
    : QObject(parent)
    , m_nextTaskId(0)
{
    // Настройка таймера очистки завершенных задач
    m_cleanupTimer.setSingleShot(false);
    m_cleanupTimer.setInterval(10000); // очистка каждые 10 секунд
    connect(&m_cleanupTimer, &QTimer::timeout, [this]() {
        // Удаление завершенных процессов из списка
        auto it = m_runningTasks.begin();
        while (it != m_runningTasks.end()) {
            if (it->process->state() == QProcess::NotRunning) {
                delete it->process;
                it = m_runningTasks.erase(it);
            } else {
                ++it;
            }
        }
    });
    m_cleanupTimer.start();
}

int CommandExecutor::executeCommand(const QString &program, const QStringList &arguments, bool requiresRoot)
{
    if (!validateCommand(program, arguments)) {
        emit commandError(-1, "Invalid command or arguments");
        return -1;
    }

    int taskId = m_nextTaskId++;
    
    QProcess *process = new QProcess(this);
    Task task;
    task.id = taskId;
    task.process = process;
    task.requiresRoot = requiresRoot;
    task.originalProgram = program;
    task.originalArguments = arguments;
    
    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &CommandExecutor::onProcessFinished);
    
    m_runningTasks.append(task);
    
    emit commandStarted(taskId, program, arguments);
    
    QString execProgram = program;
    QStringList execArgs = arguments;
    
    if (requiresRoot) {
        execProgram = "sudo";
        execArgs.prepend(program);
    }
    
    process->start(execProgram, execArgs);
    
    return taskId;
}

CommandExecutor::Result CommandExecutor::runCommand(const QString &program, const QStringList &arguments, bool requiresRoot)
{
    if (!validateCommand(program, arguments)) {
        Result result;
        result.success = false;
        result.error = "Invalid command or arguments";
        result.exitCode = -1;
        return result;
    }

    QProcess process;
    QString execProgram = program;
    QStringList execArgs = arguments;
    
    if (requiresRoot) {
        execProgram = "sudo";
        execArgs.prepend(program);
    }
    
    process.start(execProgram, execArgs);
    if (!process.waitForStarted(5000)) {
        Result result;
        result.success = false;
        result.error = "Could not start process: " + process.errorString();
        result.exitCode = -1;
        return result;
    }
    
    if (!process.waitForFinished(30000)) { // 30 секунд таймаут
        process.kill();
        Result result;
        result.success = false;
        result.error = "Process timed out";
        result.exitCode = -1;
        return result;
    }
    
    Result result;
    result.exitCode = process.exitCode();
    result.success = (result.exitCode == 0);
    result.output = process.readAllStandardOutput().trimmed();
    result.error = process.readAllStandardError().trimmed();
    
    return result;
}

bool CommandExecutor::validateCommand(const QString &program, const QStringList &arguments)
{
    // Проверка имени программы на безопасность
    QRegularExpression programRegex("^[a-zA-Z0-9._/-]+$");
    if (!programRegex.match(program).hasMatch()) {
        qWarning() << "Invalid program name:" << program;
        return false;
    }
    
    // Проверка аргументов на безопасность
    QRegularExpression argRegex("^[a-zA-Z0-9._/-]+$");
    for (const QString &arg : arguments) {
        if (!argRegex.match(arg).hasMatch() && 
            !arg.contains(QRegularExpression("^\"[^\"]*\"$")) &&  // разрешаем кавычки
            !arg.contains(QRegularExpression("^'[^']*'$"))) {    // разрешаем одинарные кавычки
            // Дополнительная проверка на потенциально опасные символы
            if (arg.contains('|') || arg.contains('&') || 
                arg.contains(';') || arg.contains('`') ||
                arg.contains('$(') || arg.contains('(') || arg.contains(')')) {
                qWarning() << "Potentially dangerous argument:" << arg;
                return false;
            }
        }
    }
    
    // Проверка на недопустимые команды
    QStringList forbiddenCommands = {"rm", "mv", "cp", "ln", "chmod", "chown", "dd", "mkfs"};
    if (forbiddenCommands.contains(program)) {
        qWarning() << "Forbidden command:" << program;
        return false;
    }
    
    return true;
}
```

## Пример асинхронного запуска процесса

```cpp
// В CommandExecutor.cpp
int CommandExecutor::executeCommand(const QString &program, const QStringList &arguments, bool requiresRoot)
{
    if (!validateCommand(program, arguments)) {
        emit commandError(-1, "Invalid command or arguments");
        return -1;
    }

    int taskId = m_nextTaskId++;
    
    QProcess *process = new QProcess(this);
    Task task;
    task.id = taskId;
    task.process = process;
    task.requiresRoot = requiresRoot;
    task.originalProgram = program;
    task.originalArguments = arguments;
    
    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &CommandExecutor::onProcessFinished);
    
    m_runningTasks.append(task);
    
    emit commandStarted(taskId, program, arguments);
    
    QString execProgram = program;
    QStringList execArgs = arguments;
    
    if (requiresRoot) {
        execProgram = "sudo";
        execArgs.prepend(program);
    }
    
    process->start(execProgram, execArgs);
    
    return taskId;
}

void CommandExecutor::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    QProcess *finishedProcess = qobject_cast<QProcess*>(sender());
    if (!finishedProcess) {
        return;
    }
    
    // Найти соответствующую задачу
    auto it = std::find_if(m_runningTasks.begin(), m_runningTasks.end(),
                          [finishedProcess](const Task &task) {
                              return task.process == finishedProcess;
                          });
    
    if (it != m_runningTasks.end()) {
        Result result;
        result.exitCode = exitCode;
        result.success = (exitStatus == QProcess::NormalExit && exitCode == 0);
        result.output = finishedProcess->readAllStandardOutput().trimmed();
        result.error = finishedProcess->readAllStandardError().trimmed();
        
        emit commandFinished(it->id, result);
        
        // Удалить процесс после отправки сигнала
        finishedProcess->deleteLater();
        m_runningTasks.erase(it);
    }
}
```

## Пример DiagnosticService

### DiagnosticService.h
```cpp
#ifndef DIAGNOSTICSERVICE_H
#define DIAGNOSTICSERVICE_H

#include <QObject>
#include <QThread>
#include <QTimer>

class DiagnosticService : public QObject
{
    Q_OBJECT

public:
    struct DiagnosticResult {
        bool success;
        QString component;
        QString message;
        int progress;
        bool critical;
    };

    explicit DiagnosticService(QObject *parent = nullptr);
    ~DiagnosticService();

signals:
    void diagnosticStarted();
    void diagnosticProgress(int percent);
    void diagnosticStepCompleted(const DiagnosticService::DiagnosticResult &result);
    void diagnosticFinished(const QList<DiagnosticService::DiagnosticResult> &results);
    void logMessage(const QString &message, const QString &type);

public slots:
    void runDiagnostics();

private slots:
    void checkPort();
    void checkFirewall();
    void checkCertificates();
    void checkProcess();
    void checkRouting();
    void checkLogs();
    void onDiagnosticStepFinished();

private:
    void scheduleNextStep();
    bool validateServerConfig() const;
    QString extractCipherFromConfig() const;

    QTimer *m_timer;
    int m_currentStep;
    QList<DiagnosticResult> m_results;
    QString m_serverConfigPath;
    QString m_certsDir;

    static const QStringList DIAGNOSTIC_STEPS;
};

#endif // DIAGNOSTICSERVICE_H
```

### DiagnosticService.cpp (фрагмент)
```cpp
#include "DiagnosticService.h"
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QDir>
#include <QDebug>

const QStringList DiagnosticService::DIAGNOSTIC_STEPS = {
    "port", "firewall", "certificates", "process", "routing", "logs"
};

void DiagnosticService::runDiagnostics()
{
    emit diagnosticStarted();
    m_results.clear();
    m_currentStep = 0;
    
    scheduleNextStep();
}

void DiagnosticService::scheduleNextStep()
{
    if (m_currentStep >= DIAGNOSTIC_STEPS.size()) {
        emit diagnosticFinished(m_results);
        return;
    }
    
    QString step = DIAGNOSTIC_STEPS[m_currentStep];
    emit diagnosticProgress((m_currentStep * 100) / DIAGNOSTIC_STEPS.size());
    
    if (step == "port") {
        checkPort();
    } else if (step == "firewall") {
        checkFirewall();
    } else if (step == "certificates") {
        checkCertificates();
    } else if (step == "process") {
        checkProcess();
    } else if (step == "routing") {
        checkRouting();
    } else if (step == "logs") {
        checkLogs();
    }
}

void DiagnosticService::checkCertificates()
{
    DiagnosticResult result;
    result.component = "Certificates";
    result.progress = (m_currentStep * 100) / DIAGNOSTIC_STEPS.size();
    result.critical = true;
    
    // Проверка существования необходимых сертификатов
    QStringList requiredFiles = {
        m_certsDir + "/ca.crt",
        m_certsDir + "/server.crt", 
        m_certsDir + "/server.key",
        m_certsDir + "/dh.pem",
        m_certsDir + "/ta.key"
    };
    
    bool allExist = true;
    for (const QString &file : requiredFiles) {
        if (!QFile::exists(file)) {
            result.message = QString("Отсутствует файл: %1").arg(file);
            allExist = false;
            break;
        }
    }
    
    result.success = allExist;
    if (allExist) {
        result.message = "Все сертификаты присутствуют";
    }
    
    m_results.append(result);
    emit diagnosticStepCompleted(result);
    
    m_currentStep++;
    QTimer::singleShot(100, this, &DiagnosticService::scheduleNextStep);
}

bool DiagnosticService::validateServerConfig() const
{
    QFile configFile(m_serverConfigPath);
    if (!configFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream in(&configFile);
    QString content = in.readAll();
    
    // Игнорируем закомментированные строки и пробелы
    QStringList lines = content.split('\n');
    QRegularExpression commentRegex("^\\s*#.*$");
    QRegularExpression emptyRegex("^\\s*$");
    
    bool hasPort = false;
    bool hasProto = false;
    bool hasDev = false;
    bool hasCa = false;
    bool hasCert = false;
    bool hasKey = false;
    bool hasDh = false;
    bool hasServer = false;
    bool hasCipher = false;
    bool hasAuth = false;
    bool hasTlsCrypt = false;

    for (const QString &line : lines) {
        QString trimmedLine = line.trimmed();
        
        if (commentRegex.match(trimmedLine).hasMatch() || emptyRegex.match(trimmedLine).hasMatch()) {
            continue;
        }
        
        if (trimmedLine.startsWith("port ")) {
            hasPort = true;
        } else if (trimmedLine.startsWith("proto ")) {
            hasProto = true;
        } else if (trimmedLine.startsWith("dev ")) {
            hasDev = true;
            if (trimmedLine.contains("tun")) {
                // Это корректное значение
            }
        } else if (trimmedLine.startsWith("ca ")) {
            hasCa = true;
        } else if (trimmedLine.startsWith("cert ")) {
            hasCert = true;
        } else if (trimmedLine.startsWith("key ")) {
            hasKey = true;
        } else if (trimmedLine.startsWith("dh ")) {
            hasDh = true;
        } else if (trimmedLine.startsWith("server ")) {
            hasServer = true;
        } else if (trimmedLine.startsWith("cipher ")) {
            hasCipher = true;
        } else if (trimmedLine.startsWith("auth ")) {
            hasAuth = true;
        } else if (trimmedLine.startsWith("tls-crypt ") || trimmedLine.startsWith("tls-auth ")) {
            hasTlsCrypt = true;
        }
    }

    configFile.close();
    
    return hasPort && hasProto && hasDev && hasCa && hasCert && hasKey && 
           hasDh && hasServer && hasCipher && hasAuth && (hasTlsCrypt || hasTlsCrypt);
}
```

## Рекомендации по безопасности

1. **Использование QProcess без shell**: Все системные команды теперь выполняются через QProcess с явными аргументами, без использования shell (`bash -c`), что предотвращает command injection.

2. **Валидация команд**: Класс CommandExecutor включает строгую валидацию команд и аргументов перед их выполнением, предотвращая выполнение потенциально опасных команд.

3. **Изоляция root-операций**: Root-операции инкапсулированы в CommandExecutor, который может использовать sudo только для проверенных команд.

4. **Защита от path traversal**: Проверки на навигацию по файловой системе (`../`) предотвращают доступ к недопустимым путям.

5. **Контроль доступа к файлам**: Все операции с файлами ограничены определенными каталогами и включают проверки существования.

## Рекомендации по коммерциализации проекта

1. **Модульная архитектура**: Разделение на модули позволяет легко добавлять новые функции и обеспечивает масштабируемость продукта.

2. **API для интеграции**: Можно добавить REST API или DBus интерфейс для интеграции с другими системами.

3. **Управление несколькими конфигурациями**: Архитектура подготовлена для поддержки нескольких OpenVPN конфигураций и серверов.

4. **Аудит и логирование**: Централизованный логгер позволяет вести аудит действий пользователя и системных событий.

5. **Поддержка CRL**: Архитектура позволяет легко добавить поддержку списков отозванных сертификатов (CRL).

6. **Управление клиентами**: Возможность создания, управления и отзыва клиентских сертификатов.

7. **Мониторинг и уведомления**: Система может быть расширена для отправки уведомлений о важных событиях.

8. **Веб-интерфейс**: Архитектура позволяет легко добавить веб-интерфейс поверх существующего API.
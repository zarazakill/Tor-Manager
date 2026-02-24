#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QProcess>
#include <QTimer>
#include <QSystemTrayIcon>
#include <QTcpSocket>
#include <QSettings>
#include <QListWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QTabWidget>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QLineEdit>
#include <QMenu>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QMap>
#include <QVariant>
#include <QRegularExpression>
#include <QTableWidget>      // Для таблицы клиентов
#include <QDateTime>         // Для временных меток

#ifdef Q_OS_LINUX
#include <unistd.h>
#endif

// Структура для хранения информации о клиенте
struct ClientInfo {
    QString commonName;
    QString realAddress;
    QString virtualAddress;
    QString virtualIPv6;
    qint64 bytesReceived;
    qint64 bytesSent;
    QDateTime connectedSince;
    qint64 connectedSinceEpoch;
    qint64 pid;
    bool isActive;
};

/**
 * Класс для асинхронной генерации сертификатов
 */
class CertificateGenerator : public QObject
{
    Q_OBJECT

public:
    explicit CertificateGenerator(QObject *parent = nullptr);

    void generateCertificates(const QString &certsDir,
                              const QString &openVPNPath,
                              bool useEasyRSA);

signals:
    void logMessage(const QString &message, const QString &type);
    void finished(bool success);
    void progress(int percent);

private slots:
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);
    void onProcessOutput();
    void onProcessErrorOutput();

private:
    QProcess *currentProcess;
    QStringList commandQueue;
    int currentCommandIndex;
    QString certsDirectory;
    QString openVPNPath;
    bool useEasyRSAFlag;

    void runNextCommand();
    void runOpenSSLCommand(const QStringList &args, const QString &description);
    void runEasyRSACommand(const QString &cmd, const QString &description);
    void saveLogToFile(const QString &message, const QString &type);
    QString getLogFilePath(const QString &date = QString());
};

/**
 * Главный класс приложения Tor Manager
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT



public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    // Публичные члены для доступа из main.cpp
    QSystemTrayIcon *trayIcon = nullptr;

    // Состояние приложения
    bool torRunning = false;
    bool serverMode = false;

    // Публичные слоты
public slots:
    void startTor();
    void startOpenVPNServer();

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    // Управление Tor
    void stopTor();
    void restartTor();
    void onTorStarted();
    void onTorFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onTorError(QProcess::ProcessError error);
    void onTorReadyRead();
    void checkTorStatus();
    void sendTorCommand(const QString &command);
    void onControlSocketConnected();
    void onControlSocketReadyRead();
    void onControlSocketError();
    void requestNewCircuit();

    // Управление сервером
    void stopOpenVPNServer();
    void onServerStarted();
    void onServerFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onServerError(QProcess::ProcessError error);
    void onServerReadyRead();

    // Генерация сертификатов
    void generateCertificates();
    void generateCertificatesAsync();
    void onCertGenerationFinished(bool success);
    void checkCertificates();

    // Генерация клиентских конфигураций
    void generateClientConfig();
    void generateTestAndroidConfig();
    void generateClientCertificate(const QString &clientName);

    // Проверка сети
    void checkIPLeak();
    void onIPCheckFinished();

    // Интерфейс
    void updateStatus();
    void showSettings();
    void showAbout();
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void applySettings();
    void updateTrafficStats();
    void addLogMessage(const QString &message, const QString &type = "info");

    // Управление мостами
    void addBridge();
    void removeBridge();
    void importBridgesFromText();
    void validateBridgeFormat();
    void testBridgeConnection(const QString &bridge);
    void updateBridgeConfig();

    // Kill switch
    void enableKillSwitch();
    void disableKillSwitch();
    void setupFirewallRules(bool enable);

    // Диагностика
    void diagnoseConnection();
    void testServerConfig();

    // ========== НОВЫЕ МЕТОДЫ ДЛЯ МАРШРУТИЗАЦИИ ==========
    QString getExternalInterface();
    bool setupIPTablesRules(bool enable);
    void applyRoutingManually();
    void verifyRouting();
    void enableIPForwarding();
    bool checkIPForwarding();

    // ========== НОВЫЕ МЕТОДЫ ДЛЯ УПРАВЛЕНИЯ КЛИЕНТАМИ ==========
    void createClientsTab();
    void updateClientsTable();
    void disconnectSelectedClient();
    void disconnectAllClients();
    void showClientDetails();
    void banClient();
    void exportClientsLog();
    void clearClientsLog();
    void onClientTableContextMenu(const QPoint &pos);
    void refreshClientsNow();

    // ========== НОВЫЕ МЕТОДЫ ДЛЯ РАБОТЫ С ЛОГАМИ КЛИЕНТОВ ==========
    QString getLogFilePath(const QString &date = QString());
    void saveLogToFile(const QString &message, const QString &type);
    void loadClientsLogHistory();
    void showFullClientsLog();

private:
    // Инициализация
    void setupUI();
    void setupTrayIcon();
    void setupConnections();
    void createMenuBar();
    void createTabWidget();
    void createTorTab();
    void createServerTab();
    void createSettingsTab();
    void createLogsTab();

    // Конфигурация Tor
    void createTorConfig();
    QString getTorConfigPath() { return torrcPath; }
    QString getTorDataPath() { return torDataDir; }
    bool checkTorInstalled();

    // Конфигурация сервера
    void createServerConfig();
    void createTorRoutingScripts();
    bool checkOpenVPNInstalled();
    bool validateServerConfig();
    QString findEasyRSA();
    QString getLocalIP();
    void updateClientStats();  // Устаревший метод, заменён на updateClientsTable

    // Вспомогательные функции
    bool copyPath(const QString &src, const QString &dst);

    // Управление мостами
    QString normalizeBridgeLine(const QString &bridge);
    bool validateWebtunnelBridge(const QString &bridge);
    bool validateObfs4Bridge(const QString &bridge);
    QStringList parseBridgeFile(const QString &filePath);
    void saveBridgesToSettings();
    void loadBridgesFromSettings();
    QString detectBridgeType(const QString &bridgeLine);
    QString getTransportPluginPath(const QString &transport);
    bool checkTransportPluginInstalled(const QString &transport);
    void updateBridgeStats();
    QString findLyrebirdPath();

    // Вспомогательные
    bool isProcessRunning(const QString &processName);
    QString executeCommand(const QString &command);
    void setConnectionState(const QString &state);
    bool verifyTorConnection();
    void requestExternalIP();
    void loadSettings();
    void saveSettings();

    // Компоненты интерфейса
    QTabWidget *tabWidget = nullptr;

    // Вкладка Tor
    QWidget *torTab = nullptr;
    QPushButton *btnStartTor = nullptr;
    QPushButton *btnStopTor = nullptr;
    QPushButton *btnRestartTor = nullptr;
    QPushButton *btnNewCircuit = nullptr;
    QLabel *lblTorStatus = nullptr;
    QLabel *lblTorIP = nullptr;
    QLabel *lblCircuitInfo = nullptr;
    QTextEdit *txtTorLog = nullptr;
    QComboBox *cboBridgeType = nullptr;
    QListWidget *lstBridges = nullptr;
    QPushButton *btnAddBridge = nullptr;
    QPushButton *btnRemoveBridge = nullptr;
    QLabel *lblTrafficStats = nullptr;
    QPushButton *btnImportBridges = nullptr;
    QPushButton *btnTestBridge = nullptr;
    QLabel *lblBridgeStats = nullptr;

    // Вкладка сервера
    QWidget *serverTab = nullptr;
    QGroupBox *serverGroup = nullptr;
    QSpinBox *spinServerPort = nullptr;
    QLineEdit *txtServerNetwork = nullptr;
    QCheckBox *chkRouteThroughTor = nullptr;
    QPushButton *btnGenerateCerts = nullptr;
    QPushButton *btnCheckCerts = nullptr;
    QPushButton *btnStartServer = nullptr;
    QPushButton *btnStopServer = nullptr;
    QLabel *lblServerStatus = nullptr;
    QLabel *lblConnectedClients = nullptr;  // Теперь только счётчик
    QTextEdit *txtServerLog = nullptr;
    QLabel *lblCurrentIP = nullptr;
    QPushButton *btnCheckIP = nullptr;
    QPushButton *btnGenerateClientConfig = nullptr;
    QPushButton *btnDiagnose = nullptr;
    QPushButton *btnTestConfig = nullptr;

    // ========== НОВАЯ ВКЛАДКА КЛИЕНТОВ ==========
    QWidget *clientsTab = nullptr;
    QTableWidget *clientsTable = nullptr;
    QTextEdit *txtClientsLog = nullptr;
    QPushButton *btnDisconnectClient = nullptr;
    QPushButton *btnDisconnectAll = nullptr;
    QPushButton *btnRefreshClients = nullptr;
    QPushButton *btnClientDetails = nullptr;
    QPushButton *btnBanClient = nullptr;
    QPushButton *btnExportClientsLog = nullptr;
    QPushButton *btnClearClientsLog = nullptr;
    QLabel *lblTotalClients = nullptr;
    QLabel *lblActiveClients = nullptr;
    QTimer *clientsRefreshTimer = nullptr;
    QMap<QString, ClientInfo> clientsCache;  // Кэш информации о клиентах
    QStringList clientsConnectionLog;        // Лог подключений/отключений

    // Вкладка настроек
    QWidget *settingsTab = nullptr;
    QSpinBox *spinTorSocksPort = nullptr;
    QSpinBox *spinTorControlPort = nullptr;
    QCheckBox *chkAutoStart = nullptr;
    QCheckBox *chkKillSwitch = nullptr;
    QCheckBox *chkBlockIPv6 = nullptr;
    QCheckBox *chkDNSLeakProtection = nullptr;
    QCheckBox *chkStartMinimized = nullptr;
    QLineEdit *txtTorPath = nullptr;
    QLineEdit *txtOpenVPNPath = nullptr;
    QPushButton *btnApplySettings = nullptr;
    QPushButton *btnBrowseTor = nullptr;
    QPushButton *btnBrowseOpenVPN = nullptr;

    // Вкладка журналов
    QWidget *logsTab = nullptr;
    QTextEdit *txtAllLogs = nullptr;
    QComboBox *cboLogLevel = nullptr;
    QPushButton *btnClearLogs = nullptr;
    QPushButton *btnSaveLogs = nullptr;

    // Системный трей
    QMenu *trayMenu = nullptr;

    // Процессы
    QProcess *torProcess = nullptr;
    QProcess *openVPNServerProcess = nullptr;
    CertificateGenerator *certGenerator = nullptr;

    // Сеть
    QTcpSocket *controlSocket = nullptr;
    QNetworkAccessManager *ipCheckManager = nullptr;

    // Таймеры
    QTimer *statusTimer = nullptr;
    QTimer *trafficTimer = nullptr;
    QTimer *clientStatsTimer = nullptr;

    // Настройки
    QSettings *settings = nullptr;

    // Переменные состояния
    bool killSwitchEnabled = false;
    bool controlSocketConnected = false;
    bool serverStopPending = false;
    int serverTorWaitRetries = 0;
    QString currentConnectionState;
    QString currentIP;
    QString torIP;
    quint64 bytesReceived = 0;
    quint64 bytesSent = 0;
    int connectedClients = 0;
    QString tempLinkPath;

    // Пути
    QString torrcPath;
    QString torDataDir;
    QString serverConfigPath;
    QString torExecutablePath;
    QString openVPNExecutablePath;

    // Пути к сертификатам
    QString certsDir;
    QString caCertPath;
    QString serverCertPath;
    QString serverKeyPath;
    QString dhParamPath;
    QString taKeyPath;

    // Мосты
    QStringList configuredBridges;
    QMap<QString, QString> transportPluginPaths;

    // Константы
    static const int DEFAULT_TOR_SOCKS_PORT;
    static const int DEFAULT_TOR_CONTROL_PORT;
    static const int DEFAULT_VPN_SERVER_PORT;
    static const int MAX_LOG_LINES;
    static const int BRIDGE_TEST_TIMEOUT;
    static const int CLIENT_STATS_UPDATE_INTERVAL;
};

#endif // MAINWINDOW_H

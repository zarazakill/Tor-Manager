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
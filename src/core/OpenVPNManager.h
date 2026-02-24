#ifndef OPENVPNMANAGER_H
#define OPENVPNMANAGER_H

#include <QObject>
#include <QProcess>
#include <QTimer>
#include <QString>
#include <QMap>
#include "../utils/CommandExecutor.h"

// Forward declaration
class CommandExecutor;

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

class OpenVPNManager : public QObject
{
    Q_OBJECT

public:
    enum class Status {
        Stopped,
        Starting,
        Running,
        Error
    };

    explicit OpenVPNManager(CommandExecutor *executor, QObject *parent = nullptr);
    ~OpenVPNManager();

    Status getStatus() const;
    int getConnectedClientsCount() const;
    QList<ClientInfo> getClients() const;

signals:
    void statusChanged(Status status);
    void logMessage(const QString &message, const QString &type);
    void clientConnected(const ClientInfo &client);
    void clientDisconnected(const QString &commonName);
    void connectedClientsCountChanged(int count);

public slots:
    void start(const QString &configPath);
    void stop();
    void restart();

private slots:
    void onProcessStarted();
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);
    void onProcessOutput();
    void updateClientStats();

private:
    void parseManagementInterfaceOutput(const QString &output);
    bool validateServerConfig(const QString &configPath) const;
    QString extractCipherFromConfig(const QString &configPath) const;

    QProcess *m_process;
    QTimer *m_statsTimer;
    CommandExecutor *m_commandExecutor;
    
    Status m_currentStatus;
    int m_connectedClientsCount;
    QList<ClientInfo> m_clients;
    
    QString m_configPath;
    QString m_managementAddress;
    int m_managementPort;
    
    static const int DEFAULT_MANAGEMENT_PORT;
};

#endif // OPENVPNMANAGER_H
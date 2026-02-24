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
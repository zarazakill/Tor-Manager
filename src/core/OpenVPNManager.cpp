#include "OpenVPNManager.h"
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QTimer>
#include <QRegularExpression>
#include <QDateTime>
#include <QDebug>

const int OpenVPNManager::DEFAULT_MANAGEMENT_PORT = 6001;

OpenVPNManager::OpenVPNManager(CommandExecutor *executor, QObject *parent)
    : QObject(parent)
    , m_process(new QProcess(this))
    , m_statsTimer(new QTimer(this))
    , m_commandExecutor(executor)
    , m_currentStatus(Status::Stopped)
    , m_connectedClientsCount(0)
    , m_managementPort(DEFAULT_MANAGEMENT_PORT)
{
    connect(m_process, &QProcess::started,
            this, &OpenVPNManager::onProcessStarted);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &OpenVPNManager::onProcessFinished);
    connect(m_process, &QProcess::errorOccurred,
            this, &OpenVPNManager::onProcessError);
    connect(m_process, &QProcess::readyReadStandardOutput,
            this, &OpenVPNManager::onProcessOutput);
    connect(m_process, &QProcess::readyReadStandardError,
            this, &OpenVPNManager::onProcessOutput);

    connect(m_statsTimer, &QTimer::timeout,
            this, &OpenVPNManager::updateClientStats);

    // Update client stats every 5 seconds
    m_statsTimer->start(5000);
}

OpenVPNManager::~OpenVPNManager()
{
    if (m_currentStatus == Status::Running) {
        stop();
    }
}

OpenVPNManager::Status OpenVPNManager::getStatus() const
{
    return m_currentStatus;
}

int OpenVPNManager::getConnectedClientsCount() const
{
    return m_connectedClientsCount;
}

QList<ClientInfo> OpenVPNManager::getClients() const
{
    return m_clients;
}

void OpenVPNManager::start(const QString &configPath)
{
    if (m_currentStatus != Status::Stopped) {
        emit logMessage("OpenVPN сервер уже запущен или запускается", "warning");
        return;
    }

    if (!QFile::exists(configPath)) {
        emit logMessage("Конфигурационный файл не существует: " + configPath, "error");
        return;
    }

    if (!validateServerConfig(configPath)) {
        emit logMessage("Конфигурационный файл содержит ошибки", "error");
        return;
    }

    emit logMessage("Запуск OpenVPN сервера...", "info");
    m_currentStatus = Status::Starting;
    emit statusChanged(m_currentStatus);

    m_configPath = configPath;

    // Start OpenVPN process
    QStringList arguments;
    arguments << "--config" << configPath;
    // Add management interface for client monitoring
    arguments << "--management" << "127.0.0.1" << QString::number(m_managementPort);
    arguments << "--management-hold";  // Hold until we explicitly release

    m_process->start("openvpn", arguments);
}

void OpenVPNManager::stop()
{
    if (m_currentStatus != Status::Running && m_currentStatus != Status::Starting) {
        emit logMessage("OpenVPN сервер не запущен", "warning");
        return;
    }

    emit logMessage("Остановка OpenVPN сервера...", "info");

    if (m_process->state() == QProcess::Running) {
        m_process->terminate();
        if (!m_process->waitForFinished(3000)) {
            m_process->kill();
            m_process->waitForFinished(1000);
        }
    }

    m_currentStatus = Status::Stopped;
    m_connectedClientsCount = 0;
    m_clients.clear();
    emit connectedClientsCountChanged(m_connectedClientsCount);
    emit statusChanged(m_currentStatus);
    emit logMessage("OpenVPN сервер остановлен", "info");
}

void OpenVPNManager::restart()
{
    stop();
    QTimer::singleShot(1000, this, [this]() {
        if (!m_configPath.isEmpty()) {
            start(m_configPath);
        }
    });
}

void OpenVPNManager::onProcessStarted()
{
    m_currentStatus = Status::Running;
    emit statusChanged(m_currentStatus);
    emit logMessage("OpenVPN сервер успешно запущен", "success");
}

void OpenVPNManager::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_currentStatus != Status::Stopped) {
        m_currentStatus = Status::Stopped;
        m_connectedClientsCount = 0;
        m_clients.clear();
        emit connectedClientsCountChanged(m_connectedClientsCount);
        emit statusChanged(m_currentStatus);
        
        if (exitStatus == QProcess::NormalExit && exitCode == 0) {
            emit logMessage("OpenVPN сервер завершен нормально", "info");
        } else {
            emit logMessage(QString("OpenVPN сервер завершен с кодом %1").arg(exitCode), "error");
        }
    }
}

void OpenVPNManager::onProcessError(QProcess::ProcessError error)
{
    QString errorStr;
    switch (error) {
        case QProcess::FailedToStart:
            errorStr = "Не удалось запустить процесс OpenVPN";
            break;
        case QProcess::Crashed:
            errorStr = "Процесс OpenVPN аварийно завершился";
            break;
        case QProcess::Timedout:
            errorStr = "Таймаут процесса OpenVPN";
            break;
        default:
            errorStr = "Неизвестная ошибка процесса OpenVPN";
    }

    m_currentStatus = Status::Error;
    emit statusChanged(m_currentStatus);
    emit logMessage("Ошибка OpenVPN: " + errorStr, "error");
}

void OpenVPNManager::onProcessOutput()
{
    QString output = m_process->readAllStandardOutput();
    QString error = m_process->readAllStandardError();

    if (!output.isEmpty()) {
        emit logMessage(output.trimmed(), "info");
        // Check if output contains client connection/disconnection info
        parseManagementInterfaceOutput(output);
    }
    if (!error.isEmpty()) {
        emit logMessage(error.trimmed(), "error");
    }
}

void OpenVPNManager::updateClientStats()
{
    // In a real implementation, we would connect to the management interface
    // and request client list using the 'status' command
    // For now, just emit the current count
    
    if (m_currentStatus == Status::Running) {
        emit connectedClientsCountChanged(m_connectedClientsCount);
    }
}

void OpenVPNManager::parseManagementInterfaceOutput(const QString &output)
{
    // Parse management interface output to extract client information
    QStringList lines = output.split('\n');
    for (const QString &line : lines) {
        if (line.contains("CLIENT_LIST")) {
            // Parse client list entry
            QStringList parts = line.split(',');
            if (parts.size() >= 8) {
                ClientInfo client;
                client.commonName = parts[1];
                client.realAddress = parts[2];
                client.virtualAddress = parts[3];
                client.virtualIPv6 = parts[4];
                
                client.bytesReceived = parts[5].toLongLong();
                client.bytesSent = parts[6].toLongLong();
                
                client.connectedSinceEpoch = parts[7].toLongLong();
                client.connectedSince = QDateTime::fromSecsSinceEpoch(client.connectedSinceEpoch);
                client.pid = parts[8].toLongLong();
                client.isActive = true;
                
                // Check if this is a new client or update existing
                bool found = false;
                for (int i = 0; i < m_clients.size(); ++i) {
                    if (m_clients[i].commonName == client.commonName) {
                        m_clients[i] = client;
                        found = true;
                        break;
                    }
                }
                
                if (!found) {
                    m_clients.append(client);
                    emit clientConnected(client);
                }
                
                m_connectedClientsCount = m_clients.size();
                emit connectedClientsCountChanged(m_connectedClientsCount);
            }
        }
        else if (line.contains("CLIENT:DISCONNECT")) {
            // Handle client disconnection
            QRegularExpression regex("CLIENT:DISCONNECT (\\w+)");
            QRegularExpressionMatch match = regex.match(line);
            if (match.hasMatch()) {
                QString commonName = match.captured(1);
                
                // Remove client from list
                for (int i = 0; i < m_clients.size(); ++i) {
                    if (m_clients[i].commonName == commonName) {
                        m_clients.removeAt(i);
                        emit clientDisconnected(commonName);
                        m_connectedClientsCount = m_clients.size();
                        emit connectedClientsCountChanged(m_connectedClientsCount);
                        break;
                    }
                }
            }
        }
    }
}

bool OpenVPNManager::validateServerConfig(const QString &configPath) const
{
    QFile configFile(configPath);
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
    bool hasTlsCrypt = false; // Either tls-crypt or tls-auth

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
            if (!trimmedLine.contains("tun")) {
                // Only tun devices are valid for routing through Tor
                return false;
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
           hasDh && hasServer && hasCipher && hasAuth && hasTlsCrypt;
}

QString OpenVPNManager::extractCipherFromConfig(const QString &configPath) const
{
    QFile configFile(configPath);
    if (!configFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return QString();
    }

    QTextStream in(&configFile);
    QString content = in.readAll();
    
    QStringList lines = content.split('\n');
    QRegularExpression cipherRegex(R"(^cipher\s+(.+)$)");
    
    for (const QString &line : lines) {
        QRegularExpressionMatch match = cipherRegex.match(line.trimmed());
        if (match.hasMatch()) {
            return match.captured(1);
        }
    }
    
    configFile.close();
    return QString();
}
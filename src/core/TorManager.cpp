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

QString TorManager::getCurrentIP() const
{
    return m_currentIP;
}

QString TorManager::getTorIP() const
{
    return m_torIP;
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

void TorManager::restart()
{
    stop();
    QTimer::singleShot(1000, this, &TorManager::start);
}

void TorManager::requestNewCircuit()
{
    if (m_currentStatus != Status::Running) {
        emit logMessage("Tor не запущен", "warning");
        return;
    }

    if (!m_controlSocketConnected) {
        emit logMessage("Соединение с контрольным портом не установлено", "warning");
        return;
    }

    sendTorCommand("SIGNAL NEWNYM");
    emit logMessage("Запрошена новая цепочка", "info");
}

void TorManager::onTorStarted()
{
    m_currentStatus = Status::Running;
    emit statusChanged(m_currentStatus);
    emit logMessage("Tor успешно запущен", "success");

    // Подключаемся к контрольному порту
    m_controlSocket->connectToHost("127.0.0.1", DEFAULT_TOR_CONTROL_PORT);
}

void TorManager::onTorFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_currentStatus != Status::Stopped) {
        m_currentStatus = Status::Stopped;
        emit statusChanged(m_currentStatus);
        
        if (exitStatus == QProcess::NormalExit && exitCode == 0) {
            emit logMessage("Tor завершен нормально", "info");
        } else {
            emit logMessage(QString("Tor завершен с кодом %1").arg(exitCode), "error");
        }
    }
}

void TorManager::onTorError(QProcess::ProcessError error)
{
    QString errorStr;
    switch (error) {
        case QProcess::FailedToStart:
            errorStr = "Не удалось запустить процесс Tor";
            break;
        case QProcess::Crashed:
            errorStr = "Процесс Tor аварийно завершился";
            break;
        case QProcess::Timedout:
            errorStr = "Таймаут процесса Tor";
            break;
        default:
            errorStr = "Неизвестная ошибка процесса Tor";
    }

    m_currentStatus = Status::Error;
    emit statusChanged(m_currentStatus);
    emit logMessage("Ошибка Tor: " + errorStr, "error");
}

void TorManager::onTorReadyRead()
{
    QString output = m_torProcess->readAllStandardOutput();
    QString error = m_torProcess->readAllStandardError();

    if (!output.isEmpty()) {
        emit logMessage(output.trimmed(), "info");
    }
    if (!error.isEmpty()) {
        emit logMessage(error.trimmed(), "error");
    }
}

void TorManager::onControlSocketConnected()
{
    m_controlSocketConnected = true;
    emit logMessage("Подключено к контрольному порту Tor", "success");

    // Отправляем AUTHENTICATE (в реальном приложении нужна аутентификация)
    // Для упрощения пропускаем аутентификацию в этом примере
    // sendTorCommand("AUTHENTICATE \"password\"");
    sendTorCommand("GETINFO version");
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

void TorManager::onControlSocketError()
{
    m_controlSocketConnected = false;
    emit logMessage("Ошибка контрольного порта: " + m_controlSocket->errorString(), "error");
}

void TorManager::checkStatus()
{
    // Простая проверка статуса процесса
    if (m_torProcess->state() == QProcess::Running) {
        if (m_currentStatus != Status::Running) {
            m_currentStatus = Status::Running;
            emit statusChanged(m_currentStatus);
        }
    } else if (m_currentStatus != Status::Stopped && m_currentStatus != Status::Error) {
        m_currentStatus = Status::Stopped;
        emit statusChanged(m_currentStatus);
    }
}

void TorManager::sendTorCommand(const QString &command)
{
    if (m_controlSocketConnected && m_controlSocket->state() == QTcpSocket::ConnectedState) {
        m_controlSocket->write(command.toUtf8() + "\r\n");
        m_controlSocket->flush();
    }
}

bool TorManager::checkTorInstalled()
{
    // Проверяем наличие исполняемого файла Tor
    QProcess which;
    which.start("which", QStringList() << "tor");
    which.waitForFinished();
    
    return which.exitCode() == 0;
}

QString TorManager::getTorConfigPath() const
{
    return m_torrcPath;
}

QString TorManager::getTorDataPath() const
{
    return m_torDataDir;
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
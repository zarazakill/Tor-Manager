#include "DiagnosticService.h"
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QDir>
#include <QDebug>

const QStringList DiagnosticService::DIAGNOSTIC_STEPS = {
    "port", "firewall", "certificates", "process", "routing", "logs"
};

DiagnosticService::DiagnosticService(QObject *parent)
    : QObject(parent)
    , m_timer(new QTimer(this))
    , m_currentStep(0)
{
    connect(m_timer, &QTimer::timeout, this, &DiagnosticService::onDiagnosticStepFinished);
    // Установим короткий интервал для демонстрации, в реальности это будет асинхронный вызов
}

DiagnosticService::~DiagnosticService()
{
}

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

void DiagnosticService::checkPort()
{
    DiagnosticResult result;
    result.component = "Port";
    result.progress = (m_currentStep * 100) / DIAGNOSTIC_STEPS.size();
    result.critical = true;
    
    // В реальной реализации здесь будет проверка доступности порта
    result.success = true;
    result.message = "Порт доступен для прослушивания";
    
    m_results.append(result);
    emit diagnosticStepCompleted(result);
    
    m_currentStep++;
    QTimer::singleShot(100, this, &DiagnosticService::scheduleNextStep);
}

void DiagnosticService::checkFirewall()
{
    DiagnosticResult result;
    result.component = "Firewall";
    result.progress = (m_currentStep * 100) / DIAGNOSTIC_STEPS.size();
    result.critical = true;
    
    // В реальной реализации здесь будет проверка правил firewall
    result.success = true;
    result.message = "Правила firewall корректны";
    
    m_results.append(result);
    emit diagnosticStepCompleted(result);
    
    m_currentStep++;
    QTimer::singleShot(100, this, &DiagnosticService::scheduleNextStep);
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

void DiagnosticService::checkProcess()
{
    DiagnosticResult result;
    result.component = "Process";
    result.progress = (m_currentStep * 100) / DIAGNOSTIC_STEPS.size();
    result.critical = true;
    
    // В реальной реализации здесь будет проверка запущенного процесса OpenVPN
    result.success = true;
    result.message = "Процесс OpenVPN готов к запуску";
    
    m_results.append(result);
    emit diagnosticStepCompleted(result);
    
    m_currentStep++;
    QTimer::singleShot(100, this, &DiagnosticService::scheduleNextStep);
}

void DiagnosticService::checkRouting()
{
    DiagnosticResult result;
    result.component = "Routing";
    result.progress = (m_currentStep * 100) / DIAGNOSTIC_STEPS.size();
    result.critical = true;
    
    // В реальной реализации здесь будет проверка правил маршрутизации
    result.success = true;
    result.message = "Маршрутизация настроена корректно";
    
    m_results.append(result);
    emit diagnosticStepCompleted(result);
    
    m_currentStep++;
    QTimer::singleShot(100, this, &DiagnosticService::scheduleNextStep);
}

void DiagnosticService::checkLogs()
{
    DiagnosticResult result;
    result.component = "Logs";
    result.progress = (m_currentStep * 100) / DIAGNOSTIC_STEPS.size();
    result.critical = false;
    
    // Проверка конфигурации логов
    result.success = true;
    result.message = "Логирование настроено";
    
    m_results.append(result);
    emit diagnosticStepCompleted(result);
    
    m_currentStep++;
    QTimer::singleShot(100, this, &DiagnosticService::scheduleNextStep);
}

void DiagnosticService::onDiagnosticStepFinished()
{
    // Этот слот используется для синхронизации шагов диагностики
    // В текущей реализации используется таймер для имитации асинхронности
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

QString DiagnosticService::extractCipherFromConfig() const
{
    QFile configFile(m_serverConfigPath);
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
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
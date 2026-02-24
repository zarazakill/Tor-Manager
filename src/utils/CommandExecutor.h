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
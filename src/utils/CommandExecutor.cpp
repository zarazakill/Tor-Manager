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

CommandExecutor::Result CommandExecutor::executeCommandSync(const QString &program, const QStringList &arguments, bool requiresRoot)
{
    return runCommand(program, arguments, requiresRoot);
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

QString CommandExecutor::prepareSudoCommand(const QString &program, const QStringList &arguments)
{
    QStringList cmdArgs = QStringList() << program;
    cmdArgs.append(arguments);
    return "sudo " + cmdArgs.join(" ");
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
            !arg.contains(QRegularExpression("^'[^\']*$"))) {    // разрешаем одинарные кавычки
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
    
    // Проверка на пути, которые могут быть опасны
    if (program.startsWith('/') && 
        (program.startsWith("/etc/") || program.startsWith("/usr/") || program.startsWith("/bin/") || 
         program.startsWith("/sbin/") || program.startsWith("/proc/") || program.startsWith("/sys/"))) {
        // Эти пути обычно безопасны, но нужно быть осторожным
        // Проверим дополнительно
        if (program.contains("../") || program.contains("..\\\\")) {
            qWarning() << "Path traversal detected in program:" << program;
            return false;
        }
    }
    
    return true;
}
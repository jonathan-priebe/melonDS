/*
    Copyright 2016-2025 melonDS team

    This file is part of melonDS.

    melonDS is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    melonDS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with melonDS. If not, see http://www.gnu.org/licenses/.
*/

#include "LogWindow.h"
#include <QScrollBar>

LogWindow* LogWindow::currentDlg = nullptr;
QMutex LogWindow::logMutex;
QQueue<QPair<melonDS::Platform::LogLevel, QString>> LogWindow::logQueue;

LogWindow::LogWindow(QWidget* parent) : QDialog(parent)
{
    setWindowTitle("melonDS - Log Window");
    resize(800, 600);

    QVBoxLayout* layout = new QVBoxLayout(this);

    logTextEdit = new QPlainTextEdit(this);
    logTextEdit->setReadOnly(true);
    logTextEdit->setFont(QFont("Monospace", 9));
    logTextEdit->setMaximumBlockCount(10000); // Limit to last 10000 lines
    layout->addWidget(logTextEdit);

    clearButton = new QPushButton("Clear Log", this);
    connect(clearButton, &QPushButton::clicked, this, &LogWindow::onClearClicked);
    layout->addWidget(clearButton);

    setLayout(layout);

    // Set up timer to process log queue
    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &LogWindow::processLogQueue);
    updateTimer->start(100); // Update every 100ms
}

LogWindow::~LogWindow()
{
    updateTimer->stop();
    closeDlg();
}

void LogWindow::AppendLog(melonDS::Platform::LogLevel level, const QString& message)
{
    QMutexLocker locker(&logMutex);
    logQueue.enqueue(qMakePair(level, message));
}

void LogWindow::processLogQueue()
{
    QMutexLocker locker(&logMutex);

    if (logQueue.isEmpty())
        return;

    // Process all queued messages
    while (!logQueue.isEmpty())
    {
        auto logEntry = logQueue.dequeue();
        melonDS::Platform::LogLevel level = logEntry.first;
        QString message = logEntry.second;

        QString color = getLevelColor(level);
        QString prefix = getLevelPrefix(level);

        // Build HTML formatted log line
        QString htmlLine = QString("<span style='color:%1'>[%2]</span> %3")
            .arg(color)
            .arg(prefix)
            .arg(message.toHtmlEscaped());

        logTextEdit->appendHtml(htmlLine);
    }

    // Auto-scroll to bottom
    QScrollBar* scrollBar = logTextEdit->verticalScrollBar();
    scrollBar->setValue(scrollBar->maximum());
}

void LogWindow::onClearClicked()
{
    logTextEdit->clear();
}

QString LogWindow::getLevelColor(melonDS::Platform::LogLevel level)
{
    switch (level)
    {
    case melonDS::Platform::LogLevel::Debug:
        return "#808080"; // Gray
    case melonDS::Platform::LogLevel::Info:
        return "#00AA00"; // Green
    case melonDS::Platform::LogLevel::Warn:
        return "#FF8800"; // Orange
    case melonDS::Platform::LogLevel::Error:
        return "#FF0000"; // Red
    default:
        return "#000000"; // Black
    }
}

QString LogWindow::getLevelPrefix(melonDS::Platform::LogLevel level)
{
    switch (level)
    {
    case melonDS::Platform::LogLevel::Debug:
        return "DEBUG";
    case melonDS::Platform::LogLevel::Info:
        return "INFO ";
    case melonDS::Platform::LogLevel::Warn:
        return "WARN ";
    case melonDS::Platform::LogLevel::Error:
        return "ERROR";
    default:
        return "     ";
    }
}

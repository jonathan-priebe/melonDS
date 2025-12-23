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

#ifndef LOGWINDOW_H
#define LOGWINDOW_H

#include <QDialog>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QMutex>
#include <QQueue>
#include <QTimer>

#include "Platform.h"

class LogWindow : public QDialog
{
    Q_OBJECT

public:
    explicit LogWindow(QWidget* parent = nullptr);
    ~LogWindow();

    static LogWindow* currentDlg;
    static LogWindow* openDlg(QWidget* parent)
    {
        if (currentDlg)
        {
            currentDlg->activateWindow();
            return currentDlg;
        }

        currentDlg = new LogWindow(parent);
        currentDlg->show();
        return currentDlg;
    }
    static void closeDlg()
    {
        currentDlg = nullptr;
    }

    // Thread-safe log appending
    static void AppendLog(melonDS::Platform::LogLevel level, const QString& message);

private slots:
    void processLogQueue();
    void onClearClicked();

private:
    QPlainTextEdit* logTextEdit;
    QPushButton* clearButton;
    QTimer* updateTimer;

    static QMutex logMutex;
    static QQueue<QPair<melonDS::Platform::LogLevel, QString>> logQueue;

    QString getLevelColor(melonDS::Platform::LogLevel level);
    QString getLevelPrefix(melonDS::Platform::LogLevel level);
};

#endif // LOGWINDOW_H

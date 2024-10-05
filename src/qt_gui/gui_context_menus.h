// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QClipboard>
#include <QDesktopServices>
#include <QMenu>
#include <QMessageBox>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include "cheats_patches.h"
#include "game_info.h"
#include "trophy_viewer.h"

#ifdef Q_OS_WIN
#include <ShlObj.h>
#include <Windows.h>
#include <objbase.h>
#include <shlguid.h>
#include <shobjidl.h>
#include <wrl/client.h>
#endif
#include "common/path_util.h"

class GuiContextMenus : public QObject {
    Q_OBJECT
public:
    void RequestGameMenu(const QPoint& pos, QVector<GameInfo> m_games, QTableWidget* widget,
                         bool isList) {
        QPoint global_pos = widget->viewport()->mapToGlobal(pos);
        int itemID = 0;
        if (isList) {
            itemID = widget->currentRow();
        } else {
            itemID = widget->currentRow() * widget->columnCount() + widget->currentColumn();
        }

        // Do not show the menu if an item is selected
        if (itemID == -1) {
            return;
        }

        // Setup menu.
        QMenu menu(widget);
        QAction createShortcut(tr("Create Shortcut"), widget);
        QAction openFolder(tr("Open Game Folder"), widget);
        QAction openCheats(tr("Cheats / Patches"), widget);
        QAction openSfoViewer(tr("SFO Viewer"), widget);
        QAction openTrophyViewer(tr("Trophy Viewer"), widget);

        menu.addAction(&openFolder);
        menu.addAction(&createShortcut);
        menu.addAction(&openCheats);
        menu.addAction(&openSfoViewer);
        menu.addAction(&openTrophyViewer);

        // "Copy" submenu.
        QMenu* copyMenu = new QMenu(tr("Copy info"), widget);
        QAction* copyName = new QAction(tr("Copy Name"), widget);
        QAction* copySerial = new QAction(tr("Copy Serial"), widget);
        QAction* copyNameAll = new QAction(tr("Copy All"), widget);

        copyMenu->addAction(copyName);
        copyMenu->addAction(copySerial);
        copyMenu->addAction(copyNameAll);

        menu.addMenu(copyMenu);

        // Show menu.
        auto selected = menu.exec(global_pos);
        if (!selected) {
            return;
        }

        if (selected == &openFolder) {
            QString folderPath;
            Common::FS::PathToQString(folderPath, m_games[itemID].path);
            QDesktopServices::openUrl(QUrl::fromLocalFile(folderPath));
        }

        if (selected == &openSfoViewer) {
            PSF psf;
            if (psf.Open(std::filesystem::path(m_games[itemID].path) / "sce_sys" / "param.sfo")) {
                int rows = psf.GetEntries().size();
                QTableWidget* tableWidget = new QTableWidget(rows, 2);
                tableWidget->setAttribute(Qt::WA_DeleteOnClose);
                connect(widget->parent(), &QWidget::destroyed, tableWidget,
                        [tableWidget]() { tableWidget->deleteLater(); });

                tableWidget->verticalHeader()->setVisible(false); // Hide vertical header
                int row = 0;

                for (const auto& entry : psf.GetEntries()) {
                    QTableWidgetItem* keyItem =
                        new QTableWidgetItem(QString::fromStdString(entry.key));
                    QTableWidgetItem* valueItem;
                    switch (entry.param_fmt) {
                    case PSFEntryFmt::Binary: {
                        const auto bin = psf.GetBinary(entry.key);
                        if (!bin.has_value()) {
                            valueItem = new QTableWidgetItem(QString("Unknown"));
                        } else {
                            std::string text;
                            text.reserve(bin->size() * 2);
                            for (const auto& c : *bin) {
                                static constexpr char hex[] = "0123456789ABCDEF";
                                text.push_back(hex[c >> 4 & 0xF]);
                                text.push_back(hex[c & 0xF]);
                            }
                            valueItem = new QTableWidgetItem(QString::fromStdString(text));
                        }
                    } break;
                    case PSFEntryFmt::Text: {
                        auto text = psf.GetString(entry.key);
                        if (!text.has_value()) {
                            valueItem = new QTableWidgetItem(QString("Unknown"));
                        } else {
                            valueItem =
                                new QTableWidgetItem(QString::fromStdString(std::string{*text}));
                        }
                    } break;
                    case PSFEntryFmt::Integer: {
                        auto integer = psf.GetInteger(entry.key);
                        if (!integer.has_value()) {
                            valueItem = new QTableWidgetItem(QString("Unknown"));
                        } else {
                            valueItem =
                                new QTableWidgetItem(QString("0x") + QString::number(*integer, 16));
                        }
                    } break;
                    }

                    tableWidget->setItem(row, 0, keyItem);
                    tableWidget->setItem(row, 1, valueItem);
                    keyItem->setFlags(keyItem->flags() & ~Qt::ItemIsEditable);
                    valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);
                    row++;
                }
                tableWidget->resizeColumnsToContents();
                tableWidget->resizeRowsToContents();

                int width = tableWidget->horizontalHeader()->sectionSize(0) +
                            tableWidget->horizontalHeader()->sectionSize(1) + 2;
                int height = (rows + 1) * (tableWidget->rowHeight(0));
                tableWidget->setFixedSize(width, height);
                tableWidget->sortItems(0, Qt::AscendingOrder);
                tableWidget->horizontalHeader()->setVisible(false);

                tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
                tableWidget->setWindowTitle(tr("SFO Viewer"));
                tableWidget->show();
            }
        }

        if (selected == &openCheats) {
            QString gameName = QString::fromStdString(m_games[itemID].name);
            QString gameSerial = QString::fromStdString(m_games[itemID].serial);
            QString gameVersion = QString::fromStdString(m_games[itemID].version);
            QString gameSize = QString::fromStdString(m_games[itemID].size);
            QString iconPath;
            Common::FS::PathToQString(iconPath, m_games[itemID].icon_path);
            QPixmap gameImage(iconPath);
            CheatsPatches* cheatsPatches =
                new CheatsPatches(gameName, gameSerial, gameVersion, gameSize, gameImage);
            cheatsPatches->show();
            connect(widget->parent(), &QWidget::destroyed, cheatsPatches,
                    [cheatsPatches]() { cheatsPatches->deleteLater(); });
        }

        if (selected == &openTrophyViewer) {
            QString trophyPath, gameTrpPath;
            Common::FS::PathToQString(trophyPath, m_games[itemID].serial);
            Common::FS::PathToQString(gameTrpPath, m_games[itemID].path);
            TrophyViewer* trophyViewer = new TrophyViewer(trophyPath, gameTrpPath);
            trophyViewer->show();
            connect(widget->parent(), &QWidget::destroyed, trophyViewer,
                    [trophyViewer]() { trophyViewer->deleteLater(); });
        }

        if (selected == &createShortcut) {
            QString targetPath;
            Common::FS::PathToQString(targetPath, m_games[itemID].path);
            QString ebootPath = targetPath + "/eboot.bin";

            // Get the full path to the icon
            QString iconPath;
            Common::FS::PathToQString(iconPath, m_games[itemID].icon_path);
            QFileInfo iconFileInfo(iconPath);
            QString icoPath = iconFileInfo.absolutePath() + "/" + iconFileInfo.baseName() + ".ico";

            // Path to shortcut/link
            QString linkPath;

            // Path to the shadps4.exe executable
            QString exePath;
#ifdef Q_OS_WIN
            linkPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) + "/" +
                       QString::fromStdString(m_games[itemID].name)
                           .remove(QRegularExpression("[\\\\/:*?\"<>|]")) +
                       ".lnk";

            exePath = QCoreApplication::applicationFilePath().replace("\\", "/");

#else
            linkPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) + "/" +
                       QString::fromStdString(m_games[itemID].name)
                           .remove(QRegularExpression("[\\\\/:*?\"<>|]")) +
                       ".desktop";
#endif

            // Convert the icon to .ico if necessary
            if (iconFileInfo.suffix().toLower() == "png") {
                // Convert icon from PNG to ICO
                if (convertPngToIco(iconPath, icoPath)) {

#ifdef Q_OS_WIN
                    if (createShortcutWin(linkPath, ebootPath, icoPath, exePath)) {
#else
                    if (createShortcutLinux(linkPath, ebootPath, iconPath)) {
#endif
                        QMessageBox::information(
                            nullptr, tr("Shortcut creation"),
                            QString(tr("Shortcut created successfully!\n %1")).arg(linkPath));
                    } else {
                        QMessageBox::critical(
                            nullptr, tr("Error"),
                            QString(tr("Error creating shortcut!\n %1")).arg(linkPath));
                    }
                } else {
                    QMessageBox::critical(nullptr, tr("Error"), tr("Failed to convert icon."));
                }
            } else {
                // If the icon is already in ICO format, we just create the shortcut
#ifdef Q_OS_WIN
                if (createShortcutWin(linkPath, ebootPath, iconPath, exePath)) {
#else
                if (createShortcutLinux(linkPath, ebootPath, iconPath)) {
#endif
                    QMessageBox::information(
                        nullptr, tr("Shortcut creation"),
                        QString(tr("Shortcut created successfully!\n %1")).arg(linkPath));
                } else {
                    QMessageBox::critical(
                        nullptr, tr("Error"),
                        QString(tr("Error creating shortcut!\n %1")).arg(linkPath));
                }
            }
        }

        // Handle the "Copy" actions
        if (selected == copyName) {
            QClipboard* clipboard = QGuiApplication::clipboard();
            clipboard->setText(QString::fromStdString(m_games[itemID].name));
        }

        if (selected == copySerial) {
            QClipboard* clipboard = QGuiApplication::clipboard();
            clipboard->setText(QString::fromStdString(m_games[itemID].serial));
        }

        if (selected == copyNameAll) {
            QClipboard* clipboard = QGuiApplication::clipboard();
            QString combinedText = QString("Name:%1 | Serial:%2 | Version:%3 | Size:%4")
                                       .arg(QString::fromStdString(m_games[itemID].name))
                                       .arg(QString::fromStdString(m_games[itemID].serial))
                                       .arg(QString::fromStdString(m_games[itemID].version))
                                       .arg(QString::fromStdString(m_games[itemID].size));
            clipboard->setText(combinedText);
        }
    }

    int GetRowIndex(QTreeWidget* treeWidget, QTreeWidgetItem* item) {
        int row = 0;
        for (int i = 0; i < treeWidget->topLevelItemCount(); i++) { // check top level/parent items
            QTreeWidgetItem* currentItem = treeWidget->topLevelItem(i);
            if (currentItem == item) {
                return row;
            }
            row++;

            if (currentItem->childCount() > 0) { // check child items
                for (int j = 0; j < currentItem->childCount(); j++) {
                    QTreeWidgetItem* childItem = currentItem->child(j);
                    if (childItem == item) {
                        return row;
                    }
                    row++;
                }
            }
        }
        return -1;
    }

    void RequestGameMenuPKGViewer(
        const QPoint& pos, QStringList m_pkg_app_list, QTreeWidget* treeWidget,
        std::function<void(std::filesystem::path, int, int)> InstallDragDropPkg) {
        QPoint global_pos = treeWidget->viewport()->mapToGlobal(pos); // context menu position
        QTreeWidgetItem* currentItem = treeWidget->currentItem();     // current clicked item
        int itemIndex = GetRowIndex(treeWidget, currentItem);         // row

        QMenu menu(treeWidget);
        QAction installPackage(tr("Install PKG"), treeWidget);

        menu.addAction(&installPackage);

        auto selected = menu.exec(global_pos);
        if (!selected) {
            return;
        }

        if (selected == &installPackage) {
            QStringList pkg_app_ = m_pkg_app_list[itemIndex].split(";;");
            std::filesystem::path path = Common::FS::PathFromQString(pkg_app_[9]);
            InstallDragDropPkg(path, 1, 1);
        }
    }

private:
    bool convertPngToIco(const QString& pngFilePath, const QString& icoFilePath) {
        // Load the PNG image
        QImage image(pngFilePath);
        if (image.isNull()) {
            return false;
        }

        // Scale the image to the default icon size (256x256 pixels)
        QImage scaledImage =
            image.scaled(QSize(256, 256), Qt::KeepAspectRatio, Qt::SmoothTransformation);

        // Convert the image to QPixmap
        QPixmap pixmap = QPixmap::fromImage(scaledImage);

        // Save the pixmap as an ICO file
        if (pixmap.save(icoFilePath, "ICO")) {
            return true;
        } else {
            return false;
        }
    }

#ifdef Q_OS_WIN
    bool createShortcutWin(const QString& linkPath, const QString& targetPath,
                           const QString& iconPath, const QString& exePath) {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        // Create the ShellLink object
        Microsoft::WRL::ComPtr<IShellLink> pShellLink;
        HRESULT hres = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                        IID_PPV_ARGS(&pShellLink));
        if (SUCCEEDED(hres)) {
            // Defines the path to the program executable
            pShellLink->SetPath((LPCWSTR)exePath.utf16());

            // Sets the home directory ("Start in")
            pShellLink->SetWorkingDirectory((LPCWSTR)QFileInfo(exePath).absolutePath().utf16());

            // Set arguments, eboot.bin file location
            QString arguments = QString("\"%1\"").arg(targetPath);
            pShellLink->SetArguments((LPCWSTR)arguments.utf16());

            // Set the icon for the shortcut
            pShellLink->SetIconLocation((LPCWSTR)iconPath.utf16(), 0);

            // Save the shortcut
            Microsoft::WRL::ComPtr<IPersistFile> pPersistFile;
            hres = pShellLink.As(&pPersistFile);
            if (SUCCEEDED(hres)) {
                hres = pPersistFile->Save((LPCWSTR)linkPath.utf16(), TRUE);
            }
        }

        CoUninitialize();

        return SUCCEEDED(hres);
    }
#else
    bool createShortcutLinux(const QString& linkPath, const QString& targetPath,
                             const QString& iconPath) {
        QFile shortcutFile(linkPath);
        if (!shortcutFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::critical(nullptr, "Error",
                                  QString("Error creating shortcut!\n %1").arg(linkPath));
            return false;
        }

        QTextStream out(&shortcutFile);
        out << "[Desktop Entry]\n";
        out << "Version=1.0\n";
        out << "Name=" << QFileInfo(linkPath).baseName() << "\n";
        out << "Exec=" << QCoreApplication::applicationFilePath() << " \"" << targetPath << "\"\n";
        out << "Icon=" << iconPath << "\n";
        out << "Terminal=false\n";
        out << "Type=Application\n";
        shortcutFile.close();

        return true;
    }
#endif
};

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

#include <stdio.h>
#include <QMessageBox>

#include "types.h"
#include "Platform.h"
#include "Config.h"
#include "main.h"

#include "Net.h"
#include "Net_PCap.h"

#include "WifiSettingsDialog.h"
#include "ui_WifiSettingsDialog.h"


#ifdef __WIN32__
#define PCAP_NAME "winpcap/npcap"
#else
#define PCAP_NAME "libpcap"
#endif

extern std::optional<melonDS::LibPCap> pcap;
extern melonDS::Net net;

WifiSettingsDialog* WifiSettingsDialog::currentDlg = nullptr;

bool WifiSettingsDialog::needsReset = false;

void NetInit();

WifiSettingsDialog::WifiSettingsDialog(QWidget* parent) : QDialog(parent), ui(new Ui::WifiSettingsDialog)
{
    ui->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose);

    emuInstance = ((MainWindow*)parent)->getEmuInstance();
    auto& cfg = emuInstance->getGlobalConfig();

    if (!pcap)
        pcap = melonDS::LibPCap::New();

    haspcap = pcap.has_value();
    if (pcap)
        adapters = pcap->GetAdapters();

    ui->rbDirectMode->setText("Direct mode (requires " PCAP_NAME " and ethernet connection)");

    ui->lblAdapterMAC->setText("(none)");
    ui->lblAdapterIP->setText("(none)");

    int sel = 0;
    for (int i = 0; i < adapters.size(); i++)
    {
        melonDS::AdapterData& adapter = adapters[i];

        ui->cbxDirectAdapter->addItem(QString(adapter.FriendlyName));

        if (!strncmp(adapter.DeviceName, cfg.GetString("LAN.Device").c_str(), 128))
            sel = i;
    }
    ui->cbxDirectAdapter->setCurrentIndex(sel);

    // Network mode selection
    bool direct = cfg.GetBool("LAN.DirectMode");
    bool bridge = cfg.GetBool("LAN.BridgeMode");

    if (bridge)
    {
        ui->rbBridgeMode->setChecked(true);
    }
    else if (direct)
    {
        ui->rbDirectMode->setChecked(true);
    }
    else
    {
        ui->rbIndirectMode->setChecked(true);
    }

    if (!haspcap) ui->rbDirectMode->setEnabled(false);

    // P2P settings
    bool enableP2P = cfg.GetBool("LAN.EnableP2P");
    ui->cbEnableP2P->setChecked(enableP2P);

    bool autoMode = cfg.GetBool("LAN.P2P.AutoMode");
    ui->rbP2PAuto->setChecked(autoMode);
    ui->rbP2PManual->setChecked(!autoMode);

    int portStart = cfg.GetInt("LAN.P2P.PortRangeStart");
    int portEnd = cfg.GetInt("LAN.P2P.PortRangeEnd");
    ui->spinPortRangeStart->setValue(portStart);
    ui->spinPortRangeEnd->setValue(portEnd);

    std::string externalIP = cfg.GetString("LAN.P2P.ExternalIP");
    ui->txtExternalIP->setText(QString::fromStdString(externalIP));

    // Bridge mode settings
    bool useDHCP = cfg.GetBool("LAN.Bridge.UseDHCP");
    ui->rbBridgeDHCP->setChecked(useDHCP);
    ui->rbBridgeStatic->setChecked(!useDHCP);

    std::string bridgeIP = cfg.GetString("LAN.Bridge.StaticIP");
    std::string bridgeNetmask = cfg.GetString("LAN.Bridge.Netmask");
    std::string bridgeGateway = cfg.GetString("LAN.Bridge.Gateway");

    ui->txtBridgeIP->setText(QString::fromStdString(bridgeIP));
    ui->txtBridgeNetmask->setText(QString::fromStdString(bridgeNetmask));
    ui->txtBridgeGateway->setText(QString::fromStdString(bridgeGateway));

    updateAdapterControls();
    updateP2PControls();
    updateBridgeControls();
}

WifiSettingsDialog::~WifiSettingsDialog()
{
    delete ui;
}

void WifiSettingsDialog::done(int r)
{
    if (!((MainWindow*)parent())->getEmuInstance())
    {
        QDialog::done(r);
        closeDlg();
        return;
    }

    needsReset = false;

    if (r == QDialog::Accepted)
    {
        auto& cfg = emuInstance->getGlobalConfig();

        // Network mode
        cfg.SetBool("LAN.DirectMode", ui->rbDirectMode->isChecked());
        cfg.SetBool("LAN.BridgeMode", ui->rbBridgeMode->isChecked());

        // P2P settings
        cfg.SetBool("LAN.EnableP2P", ui->cbEnableP2P->isChecked());
        cfg.SetBool("LAN.P2P.AutoMode", ui->rbP2PAuto->isChecked());
        cfg.SetInt("LAN.P2P.PortRangeStart", ui->spinPortRangeStart->value());
        cfg.SetInt("LAN.P2P.PortRangeEnd", ui->spinPortRangeEnd->value());
        cfg.SetString("LAN.P2P.ExternalIP", ui->txtExternalIP->text().toStdString());

        // Bridge mode settings
        cfg.SetBool("LAN.Bridge.UseDHCP", ui->rbBridgeDHCP->isChecked());
        cfg.SetString("LAN.Bridge.StaticIP", ui->txtBridgeIP->text().toStdString());
        cfg.SetString("LAN.Bridge.Netmask", ui->txtBridgeNetmask->text().toStdString());
        cfg.SetString("LAN.Bridge.Gateway", ui->txtBridgeGateway->text().toStdString());

        int sel = ui->cbxDirectAdapter->currentIndex();
        if (sel < 0 || sel >= adapters.size()) sel = 0;
        if (adapters.empty())
        {
            cfg.SetString("LAN.Device", "");
        }
        else
        {
            cfg.SetString("LAN.Device", adapters[sel].DeviceName);
        }

        Config::Save();
    }

    Config::Table cfg = Config::GetGlobalTable();
    std::string devicename = cfg.GetString("LAN.Device");

    NetInit();

    QDialog::done(r);

    closeDlg();
}

void WifiSettingsDialog::on_rbDirectMode_clicked()
{
    updateAdapterControls();
}

void WifiSettingsDialog::on_rbIndirectMode_clicked()
{
    updateAdapterControls();
}

void WifiSettingsDialog::on_cbxDirectAdapter_currentIndexChanged(int sel)
{
    if (!haspcap) return;

    if (sel < 0 || sel >= adapters.size() || adapters.empty()) return;

    melonDS::AdapterData* adapter = &adapters[sel];
    char tmp[64];

    snprintf(tmp, sizeof(tmp), "%02X:%02X:%02X:%02X:%02X:%02X",
             adapter->MAC[0], adapter->MAC[1], adapter->MAC[2],
             adapter->MAC[3], adapter->MAC[4], adapter->MAC[5]);
    ui->lblAdapterMAC->setText(QString(tmp));

    snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d",
             adapter->IP_v4[0], adapter->IP_v4[1],
             adapter->IP_v4[2], adapter->IP_v4[3]);
    ui->lblAdapterIP->setText(QString(tmp));
}

void WifiSettingsDialog::updateAdapterControls()
{
    bool directMode = ui->rbDirectMode->isChecked();
    bool bridgeMode = ui->rbBridgeMode->isChecked();
    bool indirectMode = ui->rbIndirectMode->isChecked();

    // Direct mode controls
    bool enableDirect = haspcap && directMode;
    ui->cbxDirectAdapter->setEnabled(enableDirect);
    ui->lblAdapterMAC->setEnabled(enableDirect);
    ui->lblAdapterIP->setEnabled(enableDirect);

    // P2P settings are only available in indirect mode
    ui->groupBox_P2P->setEnabled(indirectMode);

    // Bridge mode settings are only available in bridge mode
    ui->groupBox_Bridge->setEnabled(bridgeMode);
}

void WifiSettingsDialog::updateP2PControls()
{
    bool p2pEnabled = ui->cbEnableP2P->isChecked();
    bool manualMode = ui->rbP2PManual->isChecked();

    ui->groupBoxP2PMode->setEnabled(p2pEnabled);

    // Port range controls only enabled in manual mode
    bool enablePortRange = p2pEnabled && manualMode;
    ui->lblPortRangeStart->setEnabled(enablePortRange);
    ui->spinPortRangeStart->setEnabled(enablePortRange);
    ui->lblPortRangeTo->setEnabled(enablePortRange);
    ui->spinPortRangeEnd->setEnabled(enablePortRange);
}

void WifiSettingsDialog::on_cbEnableP2P_clicked()
{
    updateP2PControls();
}

void WifiSettingsDialog::on_rbP2PAuto_clicked()
{
    updateP2PControls();
}

void WifiSettingsDialog::on_rbP2PManual_clicked()
{
    updateP2PControls();
}

void WifiSettingsDialog::updateBridgeControls()
{
    bool staticIP = ui->rbBridgeStatic->isChecked();

    // Static IP fields only enabled when Static IP is selected
    ui->lblBridgeIP->setEnabled(staticIP);
    ui->txtBridgeIP->setEnabled(staticIP);
    ui->lblBridgeNetmask->setEnabled(staticIP);
    ui->txtBridgeNetmask->setEnabled(staticIP);
    ui->lblBridgeGateway->setEnabled(staticIP);
    ui->txtBridgeGateway->setEnabled(staticIP);
}

void WifiSettingsDialog::on_rbIndirectMode_clicked()
{
    updateAdapterControls();
}

void WifiSettingsDialog::on_rbBridgeMode_clicked()
{
    updateAdapterControls();
}

void WifiSettingsDialog::on_rbDirectMode_clicked()
{
    updateAdapterControls();
}

void WifiSettingsDialog::on_rbBridgeDHCP_clicked()
{
    updateBridgeControls();
}

void WifiSettingsDialog::on_rbBridgeStatic_clicked()
{
    updateBridgeControls();
}

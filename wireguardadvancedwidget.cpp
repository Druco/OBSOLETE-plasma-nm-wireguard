/*
    Copyright 2013 Lukas Tinkl <ltinkl@redhat.com>
    Copyright 2015 Jan Grulich <jgrulich@redhat.com>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) version 3, or any
    later version accepted by the membership of KDE e.V. (or its
    successor approved by the membership of KDE e.V.), which shall
    act as a proxy defined in Section 6 of version 3 of the license.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "wireguardadvancedwidget.h"
#include "ui_wireguardadvanced.h"
#include "nm-wireguard-service.h"
#include "settingwidget.h"
#include "wireguardutils.h"

#include <QStandardPaths>
#include <QUrl>
#include <QComboBox>

#include <KLocalizedString>
#include <KProcess>
#include <KAcceleratorManager>

class WireGuardAdvancedWidget::Private {
public:
    NetworkManager::VpnSetting::Ptr setting;
};

WireGuardAdvancedWidget::WireGuardAdvancedWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
    : QDialog(parent)
    , m_ui(new Ui::WireGuardAdvancedWidget)
    , d(new Private)
{
    m_ui->setupUi(this);

    setWindowTitle(i18nc("@title: window advanced wireguard properties", "Advanced WireGuard properties"));

    d->setting = setting;

    connect(m_ui->listenPortLineEdit, &QLineEdit::textChanged, this, &WireGuardAdvancedWidget::isListenPortValid);
    connect(m_ui->mTULineEdit, &QLineEdit::textChanged, this, &WireGuardAdvancedWidget::isMTUValid);
    connect(m_ui->tableLineEdit, &QLineEdit::textChanged, this, &WireGuardAdvancedWidget::isTableValid);
    connect(m_ui->fwMarkLineEdit, &QLineEdit::textChanged, this, &WireGuardAdvancedWidget::isFwMarkValid);
    connect(m_ui->presharedKeyLineEdit, &QLineEdit::textChanged, this, &WireGuardAdvancedWidget::isPresharedKeyValid);

    connect(m_ui->buttonBox, &QDialogButtonBox::accepted, this, &WireGuardAdvancedWidget::accept);
    connect(m_ui->buttonBox, &QDialogButtonBox::rejected, this, &WireGuardAdvancedWidget::reject);

    KAcceleratorManager::manage(this);

    if (d->setting) {
        loadConfig();
    }
}

WireGuardAdvancedWidget::~WireGuardAdvancedWidget()
{
    delete d;
}

bool WireGuardAdvancedWidget::isListenPortValid() const
{
    bool valid = WireGuardUtils::is_num_valid(m_ui->listenPortLineEdit->displayText(), 0,65535);
    bool present = (0 != m_ui->listenPortLineEdit->displayText().length());
    bool result = valid || !present;

    if (!result)
    {
        m_ui->listenPortLineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        m_ui->listenPortLineEdit->setStyleSheet("* { background-color:  }");
    }
    
    return result;
}

bool WireGuardAdvancedWidget::isMTUValid() const
{
    bool valid = WireGuardUtils::is_num_valid(m_ui->mTULineEdit->displayText());
    bool present = (0 != m_ui->mTULineEdit->displayText().length());
    bool result = valid || !present;

    if (!result)
    {
        m_ui->mTULineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        m_ui->mTULineEdit->setStyleSheet("* { background-color:  }");
    }
    
    return result;
}

bool WireGuardAdvancedWidget::isTableValid() const
{
    return true;
}

bool WireGuardAdvancedWidget::isFwMarkValid() const
{
    return true;
}

bool WireGuardAdvancedWidget::isPresharedKeyValid() const
{
    // The preshared key is not required so it is valid if not present
    bool valid = (0 == m_ui->presharedKeyLineEdit->text().length() ||
                  WireGuardUtils::is_key_valid(m_ui->presharedKeyLineEdit->text()));

    if (!valid)
    {
        m_ui->presharedKeyLineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        m_ui->presharedKeyLineEdit->setStyleSheet("* { background-color:  }");
    }
    return valid;
}

void WireGuardAdvancedWidget::loadConfig()
{
    const NMStringMap dataMap = d->setting->data();

    m_ui->listenPortLineEdit->setText(dataMap[NM_WG_KEY_LISTEN_PORT]);
    m_ui->mTULineEdit->setText(dataMap[NM_WG_KEY_MTU]);
    m_ui->tableLineEdit->setText(dataMap[NM_WG_KEY_TABLE]);
    m_ui->fwMarkLineEdit->setText(dataMap[NM_WG_KEY_FWMARK]);
    m_ui->presharedKeyLineEdit->setText(dataMap[NM_WG_KEY_PRESHARED_KEY]);
    m_ui->preUpScriptLineEdit->setText(dataMap[NM_WG_KEY_PRE_UP]);
    m_ui->postUpScriptLineEdit->setText(dataMap[NM_WG_KEY_POST_UP]);
    m_ui->preDownScriptLineEdit->setText(dataMap[NM_WG_KEY_PRE_DOWN]);
    m_ui->postDownScriptLineEdit->setText(dataMap[NM_WG_KEY_POST_DOWN]);

}

void WireGuardAdvancedWidget::setOrClear(NMStringMap &data, QLatin1String key, QString value) const
{
    if (0 != value.length())
    {
        data.insert(key, value);
    }
    else
    {
        data.remove(key);
    }
}

NetworkManager::VpnSetting::Ptr WireGuardAdvancedWidget::setting() const
{
    NMStringMap data;

    setOrClear(data, QLatin1String(NM_WG_KEY_LISTEN_PORT), m_ui->listenPortLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_MTU), m_ui->mTULineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_TABLE), m_ui->tableLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_FWMARK), m_ui->fwMarkLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_PRESHARED_KEY), m_ui->presharedKeyLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_PRE_UP), m_ui->preUpScriptLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_POST_UP), m_ui->postUpScriptLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_PRE_DOWN), m_ui->preDownScriptLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_POST_DOWN), m_ui->postDownScriptLineEdit->displayText());

    d->setting->setData(data);

    return d->setting;
}

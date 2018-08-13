/*
    Copyright 2008 Will Stephenson <wstephenson@kde.org>
    Copyright 2013 Lukáš Tinkl <ltinkl@redhat.com>

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of
    the License or (at your option) version 3 or any later version
    accepted by the membership of KDE e.V. (or its successor approved
    by the membership of KDE e.V.), which shall act as a proxy
    defined in Section 14 of version 3 of the license.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "debug.h"
#include "wireguardwidget.h"
#include "wireguardadvancedwidget.h"
#include "wireguardutils.h"

#include <QDBusMetaType>
#include <QLineEdit>
#include <QUrl>
#include <QPointer>

#include <KProcess>
#include <KUrlRequester>

#include "nm-wireguard-service.h"

class WireGuardSettingWidget::Private
{
public:
    Ui_WireGuardProp ui;
    NetworkManager::VpnSetting::Ptr setting;
};


WireGuardSettingWidget::WireGuardSettingWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
    : SettingWidget(setting, parent)
    , d(new Private)
{
    qDBusRegisterMetaType<NMStringMap>();

    d->ui.setupUi(this);
    d->setting = setting;

    connect(d->ui.addressIPv4LineEdit, &QLineEdit::textChanged, this, &WireGuardSettingWidget::isAddressValid);
    connect(d->ui.addressIPv6LineEdit, &QLineEdit::textChanged, this, &WireGuardSettingWidget::isAddressValid);
    connect(d->ui.listenPortLineEdit, &QLineEdit::textChanged, this, &WireGuardSettingWidget::isListenPortValid);
    connect(d->ui.privateKeyLineEdit, &PasswordField::textChanged, this, &WireGuardSettingWidget::isPrivateKeyValid);
    connect(d->ui.dNSLineEdit, &QLineEdit::textChanged, this, &WireGuardSettingWidget::isDNSValid);
    connect(d->ui.mTULineEdit, &QLineEdit::textChanged, this, &WireGuardSettingWidget::isMTUValid);
    connect(d->ui.publicKeyLineEdit, &QLineEdit::textChanged, this, &WireGuardSettingWidget::isPublicKeyValid);
    connect(d->ui.allowedIPsLineEdit, &QLineEdit::textChanged, this, &WireGuardSettingWidget::isAllowedIPsValid);
    connect(d->ui.endpointLineEdit, &QLineEdit::textChanged, this, &WireGuardSettingWidget::isEndpointValid);
    
    d->ui.privateKeyLineEdit->setPasswordModeEnabled(true);

    // Connect for setting check
    watchChangedSetting();
    
    KAcceleratorManager::manage(this);

    if (setting && !setting->isNull())
    {
        loadConfig(d->setting);
    }
    else
    {
        isAddressValid();
        isListenPortValid();
        isPrivateKeyValid();
        isDNSValid();
        isMTUValid();
        isPublicKeyValid();
        isAllowedIPsValid();
        isEndpointValid();
    }
}

WireGuardSettingWidget::~WireGuardSettingWidget()
{
    delete d;
}

void WireGuardSettingWidget::loadConfig(const NetworkManager::Setting::Ptr &setting)
{
    Q_UNUSED(setting)
    // General settings
    const NMStringMap dataMap = d->setting->data();

    d->ui.addressIPv4LineEdit->setText(dataMap[NM_WG_KEY_ADDR_IP4]);
    d->ui.addressIPv6LineEdit->setText(dataMap[NM_WG_KEY_ADDR_IP6]);
    d->ui.listenPortLineEdit->setText(dataMap[NM_WG_KEY_LISTEN_PORT]);
    d->ui.privateKeyLineEdit->setText(dataMap[NM_WG_KEY_PRIVATE_KEY]);
    d->ui.dNSLineEdit->setText(dataMap[NM_WG_KEY_DNS]);
    d->ui.mTULineEdit->setText(dataMap[NM_WG_KEY_MTU]);
    d->ui.publicKeyLineEdit->setText(dataMap[NM_WG_KEY_PUBLIC_KEY]);
    d->ui.allowedIPsLineEdit->setText(dataMap[NM_WG_KEY_ALLOWED_IPS]);
    d->ui.endpointLineEdit->setText(dataMap[NM_WG_KEY_ENDPOINT]);
    d->ui.presharedKeyLineEdit->setText(dataMap[NM_WG_KEY_PRESHARED_KEY]);
    
#if 0
    loadSecrets(setting);
#endif
}

void WireGuardSettingWidget::loadSecrets(const NetworkManager::Setting::Ptr &setting)
{
#if 0
    NetworkManager::VpnSetting::Ptr vpnSetting = setting.staticCast<NetworkManager::VpnSetting>();

    if (vpnSetting) {
        const QString cType = d->setting->data().value(NM_OPENVPN_KEY_CONNECTION_TYPE);
        const NMStringMap secrets = vpnSetting->secrets();

        if (cType == QLatin1String(NM_OPENVPN_CONTYPE_TLS)) {
            d->ui.x509KeyPassword->setText(secrets.value(NM_OPENVPN_KEY_CERTPASS));
        } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD)) {
            d->ui.passPassword->setText(secrets.value(NM_OPENVPN_KEY_PASSWORD));
        } else if (cType == QLatin1String(NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
            d->ui.x509PassPassword->setText(secrets.value(NM_OPENVPN_KEY_PASSWORD));
            d->ui.x509PassKeyPassword->setText(secrets.value(NM_OPENVPN_KEY_CERTPASS));
        }
    }
#endif
}

QVariantMap WireGuardSettingWidget::setting() const
{
    NMStringMap data = d->setting->data();
    NMStringMap secretData = d->setting->secrets();
    NetworkManager::VpnSetting setting;
    setting.setServiceType(QLatin1String(NM_DBUS_SERVICE_WIREGUARD));

    // required settings

    setOrClear(data, QLatin1String(NM_WG_KEY_ADDR_IP4), d->ui.addressIPv4LineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_ADDR_IP6), d->ui.addressIPv6LineEdit->displayText());

    setOrClear(data, QLatin1String(NM_WG_KEY_PRIVATE_KEY), d->ui.privateKeyLineEdit->text());
    setOrClear(data, QLatin1String(NM_WG_KEY_PUBLIC_KEY), d->ui.publicKeyLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_ALLOWED_IPS), d->ui.allowedIPsLineEdit->displayText());

    setOrClear(data, QLatin1String(NM_WG_KEY_LISTEN_PORT), d->ui.listenPortLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_DNS), d->ui.dNSLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_MTU), d->ui.mTULineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_ENDPOINT), d->ui.endpointLineEdit->displayText());
    setOrClear(data, QLatin1String(NM_WG_KEY_PRESHARED_KEY), d->ui.presharedKeyLineEdit->displayText());

    setting.setData(data);
    return setting.toMap();
}

void WireGuardSettingWidget::setOrClear(NMStringMap &data, QLatin1String key, QString value) const
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

void WireGuardSettingWidget::updateStartDir(const QUrl &url)
{
#if 0
    QList<KUrlRequester *> requesters;
    requesters << d->ui.x509CaFile << d->ui.x509Cert << d->ui.x509Key << d->ui.pskSharedKey << d->ui.passCaFile << d->ui.x509PassCaFile
               << d->ui.x509PassCert << d->ui.x509PassKey;
    Q_FOREACH (KUrlRequester * requester, requesters) {
        requester->setStartDir(url.adjusted(QUrl::RemoveFilename | QUrl::StripTrailingSlash));
    }
#endif
}

void WireGuardSettingWidget::setPasswordType(QLineEdit *edit, int type)
{
    edit->setEnabled(type == SettingWidget::EnumPasswordStorageType::Store);
}

void WireGuardSettingWidget::showAdvanced()
{
    QPointer<WireGuardAdvancedWidget> adv = new WireGuardAdvancedWidget(d->setting, this);
    adv->init();
    connect(adv.data(), &WireGuardAdvancedWidget::accepted,
            [adv, this] () {
                NetworkManager::VpnSetting::Ptr advData = adv->setting();
                if (!advData.isNull()) {
                    d->setting->setData(advData->data());
                    d->setting->setSecrets(advData->secrets());
                }
            });
    connect(adv.data(), &WireGuardAdvancedWidget::finished,
            [adv] () {
                if (adv) {
                    adv->deleteLater();
                }
            });
    adv->setModal(true);
    adv->show();
}

bool WireGuardSettingWidget::isValid() const
{
#if 0
    return !d->ui.gateway->text().isEmpty();
#endif
    return true;
}

bool WireGuardSettingWidget::isAddressValid() const
{
    bool ip4valid = WireGuardUtils::is_ip4(d->ui.addressIPv4LineEdit->displayText(), true, false);
    bool ip4present = (d->ui.addressIPv4LineEdit->displayText().length() != 0);
    bool ip6valid = WireGuardUtils::is_ip6(d->ui.addressIPv6LineEdit->displayText(), true, false);
    bool ip6present = (d->ui.addressIPv6LineEdit->displayText().length() != 0);
                   
    bool result = (ip4valid && ip6valid) ||
                  (ip4valid && !ip6present) ||
                  (!ip4present && ip6valid);

    if (!result)
    {
        d->ui.addressIPv4LineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
        d->ui.addressIPv6LineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        d->ui.addressIPv4LineEdit->setStyleSheet("* { background-color:  }");
        d->ui.addressIPv6LineEdit->setStyleSheet("* { background-color:  }");
    }
    return result;
}

bool WireGuardSettingWidget::isListenPortValid() const
{
    bool valid = WireGuardUtils::is_num_valid(d->ui.listenPortLineEdit->displayText(), 0,65535);
    bool present = (0 != d->ui.listenPortLineEdit->displayText().length());
    bool result = valid || !present;

    if (!result)
    {
        d->ui.listenPortLineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        d->ui.listenPortLineEdit->setStyleSheet("* { background-color:  }");
    }
    
    return result;
}

bool WireGuardSettingWidget::isPrivateKeyValid() const
{
    bool present = (0 != d->ui.privateKeyLineEdit->text().length());

    if (!present)
    {
        d->ui.privateKeyLineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        d->ui.privateKeyLineEdit->setStyleSheet("* { background-color:  }");
    }
    return present;
}

bool WireGuardSettingWidget::isDNSValid() const
{
    bool valid = WireGuardUtils::is_ip4(d->ui.dNSLineEdit->displayText(), false, false);
    bool present = (0 != d->ui.dNSLineEdit->displayText().length());
    bool result = valid || !present;

    if (!result)
    {
        d->ui.dNSLineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        d->ui.dNSLineEdit->setStyleSheet("* { background-color:  }");
    }
    
    return result;
}

bool WireGuardSettingWidget::isMTUValid() const
{
    bool valid = WireGuardUtils::is_num_valid(d->ui.mTULineEdit->displayText());
    bool present = (0 != d->ui.mTULineEdit->displayText().length());
    bool result = valid || !present;

    if (!result)
    {
        d->ui.mTULineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        d->ui.mTULineEdit->setStyleSheet("* { background-color:  }");
    }
    
    return result;
}

bool WireGuardSettingWidget::isPublicKeyValid() const
{
    bool present = (0 != d->ui.publicKeyLineEdit->text().length());

    if (!present)
    {
        d->ui.publicKeyLineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        d->ui.publicKeyLineEdit->setStyleSheet("* { background-color:  }");
    }
    return present;
}

bool WireGuardSettingWidget::isAllowedIPsValid() const
{
    bool result = true;
    bool present = (0 != d->ui.allowedIPsLineEdit->displayText().length());

    if (present)
    {
        // Split the string on commas
        QStringList addrs = d->ui.allowedIPsLineEdit->displayText().split(QRegExp("\\s*,\\s*"));

        for (int i = 0; i < addrs.size(); i++)
        {
            if (!WireGuardUtils::is_ip4(addrs[i], true, false) && !WireGuardUtils::is_ip6(addrs[i], true, false))
            {
                result = false;
            }
            if (!addrs[i].contains("/"))
            {
                result = false;
            }
        }
    }
    else
    {
        result = false;
    }

    if (!result)
    {
        d->ui.allowedIPsLineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        d->ui.allowedIPsLineEdit->setStyleSheet("* { background-color:  }");
    }
    
    return result;
}

bool WireGuardSettingWidget::isEndpointValid() const
{
    bool valid = WireGuardUtils::is_ip4(d->ui.endpointLineEdit->displayText(), false, true);
    bool present = (0 != d->ui.endpointLineEdit->displayText().length());
    bool result = !present || (valid &&  d->ui.endpointLineEdit->displayText().contains(":"));

    if (!result)
    {
        d->ui.endpointLineEdit->setStyleSheet("* { background-color: rgb(255,128, 128) }");
    }
    else
    {
        d->ui.endpointLineEdit->setStyleSheet("* { background-color:  }");
    }
    
    return result;
}

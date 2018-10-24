/*
    Copyright 2018 Bruce Anderson <banderson19com@san.rr.com>

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
#include "wireguardkeyvalidator.h"

class WireGuardAdvancedWidget::Private {
public:
    NetworkManager::VpnSetting::Ptr setting;
    Ui::WireGuardAdvancedWidget ui;
    QPalette warningPalette;
    QPalette normalPalette;
    WireGuardKeyValidator *keyValidator;
    QIntValidator *listenPortValidator;
    QIntValidator *mtuValidator;
    QIntValidator *fwMarkValidator;
    QRegularExpressionValidator *tableValidator;
};

WireGuardAdvancedWidget::WireGuardAdvancedWidget(const NetworkManager::VpnSetting::Ptr &setting
                                                 , QPalette normalPalette
                                                 , QPalette warningPalette
                                                 , QWidget *parent)
    : QDialog(parent)
    , d(new Private)
{
    d->normalPalette = normalPalette;
    d->warningPalette = warningPalette;
    d->keyValidator = new WireGuardKeyValidator(this);
    d->ui.setupUi(this);

    setWindowTitle(i18nc("@title: window advanced wireguard properties", "Advanced WireGuard properties"));

    d->setting = setting;

    connect(d->ui.buttonBox, &QDialogButtonBox::accepted, this, &WireGuardAdvancedWidget::accept);
    connect(d->ui.buttonBox, &QDialogButtonBox::rejected, this, &WireGuardAdvancedWidget::reject);
    connect(d->ui.presharedKeyLineEdit
            , &PasswordField::textChanged
            , this
            , &WireGuardAdvancedWidget::isPresharedKeyValid);
    connect(d->ui.tableLineEdit
            , &QLineEdit::textChanged
            , this
            , &WireGuardAdvancedWidget::isTableValid);
    d->ui.presharedKeyLineEdit->setPasswordModeEnabled(true);

    d->listenPortValidator = new QIntValidator(0, 65535, nullptr);
    d->ui.listenPortLineEdit->setValidator(d->listenPortValidator);

    d->mtuValidator = new QIntValidator(nullptr);
    d->mtuValidator->setBottom(0);
    d->ui.mtuLineEdit->setValidator(d->mtuValidator);

    d->fwMarkValidator = new QIntValidator(nullptr);
    d->fwMarkValidator->setBottom(0);
    d->ui.fwMarkLineEdit->setValidator(d->fwMarkValidator);

    d->tableValidator = new QRegularExpressionValidator(QRegularExpression("(off)|(auto)|([0-9]*)"));
    d->ui.tableLineEdit->setValidator(d->tableValidator);

    KAcceleratorManager::manage(this);

    if (d->setting) {
        loadConfig();
    }
    isPresharedKeyValid();
}

WireGuardAdvancedWidget::~WireGuardAdvancedWidget()
{
    delete d->keyValidator;
    delete d->listenPortValidator;
    delete d->mtuValidator;
    delete d->fwMarkValidator;
    delete d->tableValidator;
    delete d;
}

void WireGuardAdvancedWidget::loadConfig()
{
    const NMStringMap dataMap = d->setting->data();

    if (dataMap.contains(QLatin1String(NM_WG_KEY_LISTEN_PORT)))
        d->ui.listenPortLineEdit->setText(dataMap[NM_WG_KEY_LISTEN_PORT]);
    else
        d->ui.listenPortLineEdit->clear();

    if (dataMap.contains(QLatin1String(NM_WG_KEY_MTU)))
        d->ui.mtuLineEdit->setText(dataMap[NM_WG_KEY_MTU]);
    else
        d->ui.mtuLineEdit->clear();

    if (dataMap.contains(QLatin1String(NM_WG_KEY_TABLE)))
        d->ui.tableLineEdit->setText(dataMap[NM_WG_KEY_TABLE]);
    else
        d->ui.tableLineEdit->clear();

    if (dataMap.contains(QLatin1String(NM_WG_KEY_FWMARK)))
        d->ui.fwMarkLineEdit->setText(dataMap[NM_WG_KEY_FWMARK]);
    else
        d->ui.fwMarkLineEdit->clear();

    if (dataMap.contains(QLatin1String(NM_WG_KEY_PRESHARED_KEY)))
        d->ui.presharedKeyLineEdit->setText(dataMap[NM_WG_KEY_PRESHARED_KEY]);
    else
        d->ui.presharedKeyLineEdit->setText(QString());
}

void WireGuardAdvancedWidget::setProperty(NMStringMap &data, const QLatin1String &key, const QString &value) const
{
    if (!value.isEmpty())
        data.insert(key, value);
}

NetworkManager::VpnSetting::Ptr WireGuardAdvancedWidget::setting() const
{
    NMStringMap data;
    QString stringVal;

    setProperty(data, QLatin1String(NM_WG_KEY_LISTEN_PORT), d->ui.listenPortLineEdit->displayText());
    setProperty(data, QLatin1String(NM_WG_KEY_MTU), d->ui.mtuLineEdit->displayText());
    setProperty(data, QLatin1String(NM_WG_KEY_TABLE), d->ui.tableLineEdit->displayText());
    setProperty(data, QLatin1String(NM_WG_KEY_FWMARK), d->ui.fwMarkLineEdit->displayText());
    setProperty(data, QLatin1String(NM_WG_KEY_PRESHARED_KEY), d->ui.presharedKeyLineEdit->text());

    d->setting->setData(data);

    return d->setting;
}

bool WireGuardAdvancedWidget::isPresharedKeyValid() const
{
    int pos = 0;
    PasswordField *widget = d->ui.presharedKeyLineEdit;
    QString value = widget->text();
    bool result = QValidator::Acceptable == d->keyValidator->validate(value, pos)
        || value.isEmpty();
    setBackground(widget, result);
    return result;
}

bool WireGuardAdvancedWidget::isTableValid() const
{
    int pos = 0;
    QLineEdit *widget = d->ui.tableLineEdit;
    QString value = widget->displayText();
    bool result = QValidator::Acceptable == widget->validator()->validate(value, pos)
        || value.isEmpty();
    setBackground(widget, result);
    return result;
}

void WireGuardAdvancedWidget::setBackground(QWidget *w, bool result) const
{
    if (result)
        w->setPalette(d->normalPalette);
    else
        w->setPalette(d->warningPalette);
}

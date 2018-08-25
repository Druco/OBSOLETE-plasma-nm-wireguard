/*
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

#include "wireguard.h"
#include "wireguardutils.h"

#include <QLatin1Char>
#include <QStringBuilder>
#include <QFile>
#include <QFileInfo>
#include <KPluginFactory>
#include <KLocalizedString>
#include <KMessageBox>
#include <KStandardDirs>

#include <NetworkManagerQt/Connection>
#include <NetworkManagerQt/VpnSetting>
#include <NetworkManagerQt/Ipv4Setting>

#include "wireguardwidget.h"
#include "wireguardauth.h"

#include <arpa/inet.h>

#include "nm-wireguard-service.h"

K_PLUGIN_FACTORY_WITH_JSON(WireGuardUiPluginFactory, "plasmanetworkmanagement_wireguardui.json", registerPlugin<WireGuardUiPlugin>();)

#define NMV_WG_TAG_INTERFACE             "[Interface]"
#define NMV_WG_TAG_PRIVATE_KEY           "PrivateKey"
#define NMV_WG_TAG_LISTEN_PORT           "ListenPort"
#define NMV_WG_TAG_ADDRESS               "Address"
#define NMV_WG_TAG_DNS                   "DNS"
#define NMV_WG_TAG_MTU                   "MTU"
#define NMV_WG_TAG_TABLE                 "Table"
#define NMV_WG_TAG_PRE_UP                "PreUp"
#define NMV_WG_TAG_POST_UP               "PostUp"
#define NMV_WG_TAG_PRE_DOWN              "PreDown"
#define NMV_WG_TAG_POST_DOWN             "PostDown"
#define NMV_WG_TAG_FWMARK                "FwMark"
#define NMV_WG_ASSIGN                    "="

#define NMV_WG_TAG_PEER                  "[Peer]"
#define NMV_WG_TAG_PUBLIC_KEY            "PublicKey"
#define NMV_WG_TAG_ALLOWED_IPS           "AllowedIPs"
#define NMV_WG_TAG_ENDPOINT              "Endpoint"
#define NMV_WG_TAG_PRESHARED_KEY         "PresharedKey"


WireGuardUiPlugin::WireGuardUiPlugin(QObject * parent, const QVariantList &) : VpnUiPlugin(parent)
{
}

WireGuardUiPlugin::~WireGuardUiPlugin()
{
}

SettingWidget * WireGuardUiPlugin::widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget * parent)
{
    WireGuardSettingWidget * wid = new WireGuardSettingWidget(setting, parent);
    return wid;
}

SettingWidget * WireGuardUiPlugin::askUser(const NetworkManager::VpnSetting::Ptr &setting, QWidget * parent)
{
    return new WireGuardAuthWidget(setting, parent);
}

QString WireGuardUiPlugin::suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const
{
    return connection->id() + "_wireguard.conf";
}

QString WireGuardUiPlugin::supportedFileExtensions() const
{
    return "*.conf";
}

NMVariantMapMap WireGuardUiPlugin::importConnectionSettings(const QString &fileName)
{
    NMVariantMapMap result;

    QFile impFile(fileName);
    if (!impFile.open(QFile::ReadOnly|QFile::Text)) {
        mError = VpnUiPlugin::Error;
        mErrorMessage = i18n("Could not open file");
        return result;
    }

    const QString connectionName = QFileInfo(fileName).completeBaseName();
    NMStringMap dataMap;
    QVariantMap ipv4Data;

    QString proxy_type;
    QString proxy_user;
    QString proxy_passwd;
    bool have_address = false;
    bool have_private_key = false;
    bool have_public_key = false;
    bool have_allowed_ips = false;
    bool have_endpoint = false;

    QTextStream in(&impFile);
    enum {IDLE, INTERFACE_SECTION, PEER_SECTION} current_state = IDLE;

    while (!in.atEnd()) {
        QStringList key_value;
        QString line = in.readLine();

        // Ignore blank lines
        if (line.isEmpty()) {
            continue;
        }
        key_value.clear();
        key_value << line.split(QRegExp("\\s+=\\s*")); // Split on the ' = '

        if (key_value[0] == NMV_WG_TAG_INTERFACE)
        {
            if (current_state == IDLE)
            {
                current_state = INTERFACE_SECTION;
                continue;
            }
            else
            {
                // BAA - ERROR
                break;
            }
        }

        else if (key_value[0] == NMV_WG_TAG_PEER)
        {
            // Currently only on PEER section is allowed
            if (current_state == INTERFACE_SECTION)
            {
                current_state = PEER_SECTION;
                continue;
            }
            else
            {
                // BAA - ERROR
                break;
            }
        }

        // If we didn't get an '=' sign in the line, it's probably an error but
        // we're going to treat it as a comment and ignore it
        if (key_value.length() < 2)
            continue;

        // If we are in the [Interface] section look for the possible tags
        if (current_state == INTERFACE_SECTION)
        {
            // Address
            if (key_value[0] == NMV_WG_TAG_ADDRESS)
            {
                QStringList address_list;
                address_list << key_value[1].split(QRegExp("\\s*,\\s*"));
                for (int i = 0;i < address_list.size(); i++)
                {
                    if (WireGuardUtils::is_ip4(address_list[i]))
                    {
                        dataMap.insert(QLatin1String(NM_WG_KEY_ADDR_IP4), address_list[i]);
                        have_address = true;
                    }
                    else if (WireGuardUtils::is_ip6(address_list[i]))
                    {
                        dataMap.insert(QLatin1String(NM_WG_KEY_ADDR_IP6), address_list[i]);
                        have_address = true;
                    }
                }
            }

            // Listen Port
            else if (key_value[0] == NMV_WG_TAG_LISTEN_PORT)
            {
                if (WireGuardUtils::is_num_valid(key_value[1], 0, 65535))
                {
                    dataMap.insert(QLatin1String(NM_WG_KEY_LISTEN_PORT), key_value[1]);
                }
            }
            // Private Key
            else if (key_value[0] == NMV_WG_TAG_PRIVATE_KEY)
            {
                if (WireGuardUtils::is_key_valid(key_value[1]))
                {
                    dataMap.insert(QLatin1String(NM_WG_KEY_PRIVATE_KEY), key_value[1]);
                    have_private_key = true;
                }
            }
            // DNS
            else if (key_value[0] == NMV_WG_TAG_DNS)
            {
                if (WireGuardUtils::is_ip4(key_value[1]))
                {
                    dataMap.insert(QLatin1String(NM_WG_KEY_DNS), key_value[1]);
                }
            }
            // MTU
            else if (key_value[0] == NMV_WG_TAG_MTU)
            {
                if (WireGuardUtils::is_num_valid(key_value[1]))
                {
                    dataMap.insert(QLatin1String(NM_WG_KEY_MTU), key_value[1]);
                }
            }
            // Table
            else if (key_value[0] == NMV_WG_TAG_TABLE)
            {
                if (WireGuardUtils::is_num_valid(key_value[1]))
                {
                    dataMap.insert(QLatin1String(NM_WG_KEY_TABLE), key_value[1]);
                }
            }
            // PreUp, PostUp, PreDown and PostDown are just ignored because
            // that will be handled by the Network Manager scripts rather than
            // wg-quick
            else if (key_value[0] == NMV_WG_TAG_PRE_UP    ||
                     key_value[0] == NMV_WG_TAG_POST_UP   ||
                     key_value[0] == NMV_WG_TAG_PRE_DOWN  ||
                     key_value[0] == NMV_WG_TAG_POST_DOWN)
            {
                // TODO: maybe add these back in
            }
            else
            {
                // We got a wrong field in the Interface section so it
                // is an error
                break;
            }
        }
        else if (current_state == PEER_SECTION)
        {
            // Public Key
            if (key_value[0] == NMV_WG_TAG_PUBLIC_KEY)
            {
                if (WireGuardUtils::is_key_valid(key_value[1]))
                {
                    dataMap.insert(QLatin1String(NM_WG_KEY_PUBLIC_KEY), key_value[1]);
                    have_public_key = true;
                }
            }
            // Allowed IPs
            else if (key_value[0] == NMV_WG_TAG_ALLOWED_IPS)
            {
                if (key_value[1].length() > 0)
                {
                    dataMap.insert(QLatin1String(NM_WG_KEY_ALLOWED_IPS), key_value[1]);
                    have_allowed_ips = true;
                }
            }
            // Endpoint
            else if (key_value[0] == NMV_WG_TAG_ENDPOINT)
            {
                if (key_value[1].length() > 0)
                {
                    dataMap.insert(QLatin1String(NM_WG_KEY_ENDPOINT), key_value[1]);
                    have_endpoint = true;
                }
            }
            // Preshared Key
            else if (key_value[0] == NMV_WG_TAG_PRESHARED_KEY)
            {
                if (WireGuardUtils::is_key_valid(key_value[1]))
                {
                    dataMap.insert(QLatin1String(NM_WG_KEY_PRESHARED_KEY), key_value[1]);
                }
            }
        }
        else   // We're in IDLE or unknown state so it's an error
        {
            // TODO - add error handling
            break;
        }
    }
    if (!have_address || !have_private_key || !have_public_key || !have_endpoint || !have_allowed_ips)
    {

        mError = VpnUiPlugin::Error;
        mErrorMessage = i18n("File %1 is not a valid WireGuard configuration.", fileName);
        return result;
    }

    NetworkManager::VpnSetting setting;
    setting.setServiceType(QLatin1String(NM_DBUS_SERVICE_WIREGUARD));
    setting.setData(dataMap);

    QVariantMap conn;
    conn.insert("id", connectionName);
    conn.insert("type", "vpn");
    result.insert("connection", conn);
    result.insert("vpn", setting.toMap());

    impFile.close();
    return result;
}

QString WireGuardUiPlugin::saveFile(QTextStream &in, const QString &endTag, const QString &connectionName, const QString &fileName)
{
    const QString certificatesDirectory = KStandardDirs::locateLocal("data", "networkmanagement/certificates/" + connectionName);
    const QString absoluteFilePath = certificatesDirectory + '/' + fileName;
#if 0
    QFile outFile(absoluteFilePath);

    QDir().mkpath(certificatesDirectory);
    if (!outFile.open(QFile::WriteOnly | QFile::Text)) {
        KMessageBox::information(0, i18n("Error saving file %1: %2", absoluteFilePath, outFile.errorString()));
        return QString();
    }

    QTextStream out(&outFile);
    while (!in.atEnd()) {
        const QString line = in.readLine();

        if (line.indexOf(endTag) >= 0) {
            break;
        }

        out << line << "\n";
    }

    outFile.close();
#endif
    return absoluteFilePath;
}

bool WireGuardUiPlugin::exportConnectionSettings(const NetworkManager::ConnectionSettings::Ptr &connection, const QString &fileName)
{
    QFile expFile(fileName);
    if (! expFile.open(QIODevice::WriteOnly | QIODevice::Text) ) {
        mError = VpnUiPlugin::Error;
        mErrorMessage = i18n("Could not open file for writing");
        return false;
    }

    NMStringMap dataMap;

    NetworkManager::VpnSetting::Ptr vpnSetting = connection->setting(NetworkManager::Setting::Vpn).dynamicCast<NetworkManager::VpnSetting>();
    dataMap = vpnSetting->data();

    QString line;

    line = QString(NMV_WG_TAG_INTERFACE) + '\n';
    expFile.write(line.toLatin1());

    // Handle IPv4 and IPv6 addresses. if neither is present it is an error
    line = QString("%1 = ").arg(NMV_WG_TAG_ADDRESS);

    if (dataMap.contains(QLatin1String(NM_WG_KEY_ADDR_IP4)))
    {
        line += dataMap[NM_WG_KEY_ADDR_IP4];
        if (dataMap.contains(QLatin1String(NM_WG_KEY_ADDR_IP6)))
        {
            line += "," + dataMap[NM_WG_KEY_ADDR_IP6];
        }
    }
    else if (dataMap.contains(QLatin1String(NM_WG_KEY_ADDR_IP4)))
    {
        line += dataMap[NM_WG_KEY_ADDR_IP4];
    }
    else
    {
        return false;
    }
    line += "\n";
    expFile.write(line.toLatin1());

    // Do Private Key
    if (dataMap.contains(QLatin1String(NM_WG_KEY_PRIVATE_KEY)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_PRIVATE_KEY, dataMap[NM_WG_KEY_PRIVATE_KEY]);
    }
    else
    {
        return false;
    }
    expFile.write(line.toLatin1());
        
    // Do DNS (Not required so no error if not present)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_DNS)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_DNS, dataMap[NM_WG_KEY_DNS]);
        expFile.write(line.toLatin1());
    }

    // Do MTU (Not required so no error if not present)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_MTU)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_MTU, dataMap[NM_WG_KEY_MTU]);
        expFile.write(line.toLatin1());
    }

    // Do Table number (Not required so no error if not present)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_TABLE)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_TABLE, dataMap[NM_WG_KEY_TABLE]);
        expFile.write(line.toLatin1());
    }

    // Do Listen Port (Not required)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_LISTEN_PORT)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_LISTEN_PORT, dataMap[NM_WG_KEY_LISTEN_PORT]);
        expFile.write(line.toLatin1());
    }
        
    // Do FwMark (Not required)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_FWMARK)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_FWMARK, dataMap[NM_WG_KEY_FWMARK]);
        expFile.write(line.toLatin1());
    }
        
    // Do the Pre, Post, Up, Down scripte (Not required so no error if not present)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_PRE_UP)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_PRE_UP, dataMap[NM_WG_KEY_PRE_UP]);
        expFile.write(line.toLatin1());
    }
    if (dataMap.contains(QLatin1String(NM_WG_KEY_POST_UP)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_POST_UP, dataMap[NM_WG_KEY_POST_UP]);
        expFile.write(line.toLatin1());
    }
    if (dataMap.contains(QLatin1String(NM_WG_KEY_PRE_DOWN)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_PRE_DOWN, dataMap[NM_WG_KEY_PRE_DOWN]);
        expFile.write(line.toLatin1());
    }
    if (dataMap.contains(QLatin1String(NM_WG_KEY_POST_DOWN)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_POST_DOWN, dataMap[NM_WG_KEY_POST_DOWN]);
        expFile.write(line.toLatin1());
    }

    // Throw in the "Peer" section header
    line = "\n" + QString(NMV_WG_TAG_PEER) + '\n';
    expFile.write(line.toLatin1());

    // Do Pupblic key (required)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_PUBLIC_KEY)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_PUBLIC_KEY, dataMap[NM_WG_KEY_PUBLIC_KEY]);
    }
    else
    {
        return false;
    }
    expFile.write(line.toLatin1());
    
    // Do Allowed IP list (Required)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_ALLOWED_IPS)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_ALLOWED_IPS, dataMap[NM_WG_KEY_ALLOWED_IPS]);
    }
    else
    {
        return false;
    }
    expFile.write(line.toLatin1());


    // Do Endpoint (Not required so no error if not present)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_ENDPOINT)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_ENDPOINT, dataMap[NM_WG_KEY_ENDPOINT]);
        expFile.write(line.toLatin1());
    }

    // Do Preshared Key (Not required so no error if not present)
    if (dataMap.contains(QLatin1String(NM_WG_KEY_PRESHARED_KEY)))
    {
        line =  QString("%1 = %2\n").arg(NMV_WG_TAG_PRESHARED_KEY, dataMap[NM_WG_KEY_PRESHARED_KEY]);
        expFile.write(line.toLatin1());
    }

    expFile.close();
    return true;
}

#include "wireguard.moc"

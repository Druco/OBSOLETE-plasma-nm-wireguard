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

#include "wireguardutils.h"

// Checks to see if a string contains only number characters.
// If min and max are given, will check to see if the number is in min <= number <= max
bool WireGuardUtils::is_num_valid(QString candidate, int min, int max)
{
    if (candidate.length() == 0 ||
        candidate.indexOf(QRegExp("[^0-9]")) > -1 ||
        (candidate.toInt() > max && max != min) ||
        (candidate.toInt() < min && max != min))
    {
        return false;
    }
    else
    {
        return true;
    }
}

// check if the given string looks like an IPv4 address
// that is, four segments of numbers (0-255), separated by dots
// additionally, there may be a port suffix (separated from the address by a colon; 0 - 65535)
// and/or a subnet (separated by the rest by a slash; 0 - 32)
bool WireGuardUtils::is_ip4(QString addr, bool allow_subnet, bool allow_port)
{
	int idx = 0;
	QStringList parts;
	QStringList lastpart;

    // If we got an empty string, fail
    if (0 == addr.length())
    {
		return false;
	}

    // Split up the string at the dots
    parts << addr.split(".");

    // If there weren't 4 parts, fail
	if(parts.length() != 4)
    {
		return false;
	}

	// iterate over the first three parts, which cannot be anything else than numbers
	for(idx = 0; idx < 3; idx++)
    {
        // Check that each "chunk" contains at least one character, is all numbers, and is less than <= 255
        if (!is_num_valid(parts[idx], 0 , 255))
        {
            return false;
		}
    }

	// the last part might be just a number less than 255 or
    // have a subnet suffix after a slash (e.g. 192.168.1.254/24)
	// might have a port suffix after a colon (e.g. 192.168.1.254:8080)
    // or both: 192.168.2.1:808/24

    // First check that subnet and port are allowed
    if ((parts[3].contains("/") && false == allow_subnet) ||
        (parts[3].contains(":") && false == allow_port))
    {
        return false;
    }

    // Split on both "/" and ":" to see if it contains either a subnet mask
    // or a port
	lastpart = parts[3].split(QRegExp("[/:]"));

    // test the last octet
    if (!is_num_valid(lastpart[0], 0, 255))
    {
        return false;
    }

    // If there isn't either a netmask or a port, we're done
	if (lastpart.length() == 1)
    {
		return true;
	}

    // Split off and test the netmask if there is one
    lastpart = parts[3].split("/");

	if (lastpart.length() == 2 &&
       (!is_num_valid(lastpart[1], 0, 32)))
    {
        return false;
    }

    // Split off and test the port if there is one
    lastpart = lastpart[0].split(":");

    if (lastpart.length() == 2 &&
        (!is_num_valid(lastpart[1], 0, 65535)))
    {
        return false;
    }

	return true;
}

bool WireGuardUtils::is_ip6(QString addr, bool allow_subnet, bool allow_port)
{
	QStringList parts;
	QStringList lastpart;
    QString subnet;
    int num_parts;
    int part_length[8];
    int num_empty = 0;
    bool has_subnet = false;

    // If we got an empty string, fail
    if (0 == addr.length())
    {
		return false;
	}

    // Split up the string at the cololn
    parts << addr.split(":");
    num_parts = parts.size();

    // If there aren't at least 2 parts, and at most 8 fail
	if(num_parts < 3 || num_parts > 8)
    {
		return false;
	}

    // Separate out the last (possibly blank) hextet and the netmask if it has one
    lastpart = parts[num_parts-1].split("/");
    if (lastpart.size() > 1)
    {
        if (false == allow_subnet)
        {
            return false;
        }
        has_subnet = true;
        subnet = lastpart[1];
        if (0 == subnet.length())
        {
            return false;
        }
        parts[num_parts-1] = lastpart[0];
    }

    // Count the number of blank fields
    for (int i = 0; i < num_parts; i++)
    {
        part_length[i] = parts[i].length();
        if (part_length[i] == 0)
        {
            num_empty++;
        }
    }

    // If there are more than 3 empty hextets it's an error
    if (num_empty > 3)
    {
        return false;
    }

    // If there are 3 empty hextets there must only be the 3 (i.e. ::)
    else if (num_empty == 3 && num_parts != 3)
    {
        return false;
    }

    // if there are 2 empty hextets they must either be the first 2 or last 2
    else if (num_empty == 2 &&
             !(part_length[0] == 0 && part_length[1] == 0) &&
             !(part_length[num_parts-1] == 0 && part_length[num_parts-2] == 0))
    {
        return false;
    }

    // If there is just 1 empty it must not be first or last
    else if (num_empty == 1 &&
             (0 == part_length[0] || 0 == part_length[num_parts-1]))
    {
        return false;
    }

    // If there are less than 8 parts there must be at least 1 empty
    if (num_parts < 8 && (0 == num_empty || (1 == num_empty && 0 == part_length[num_parts-1])))
    {
        return false;
    }

    // Now just check that the hextets is valid
    for (int i = 0; i < num_parts; i++)
    {
        if (0 == part_length[i])
        {
            continue;
        }
        else if (part_length[i] > 4)
        {
            return false;
        }
        else if (parts[i].indexOf(QRegExp("[^0-9A-Fa-f]")) > -1)
        {
            return false;
        }
    }

    // Check the netmask
    if (has_subnet && !is_num_valid(subnet, 0, 128))
    {
        return false;
    }

    return true;
}

// Check if a string is a valid WireGuard key which should be
// 44 characters long and composed alphanumeric characters, plus
// sign, and slash with the last one being an equal sign.
bool WireGuardUtils::is_key_valid(QString candidate)
{
    if (44 != candidate.length() ||
        43 != candidate.indexOf(QRegExp("[^a-zA-Z0-9+/]")) ||
        43 != candidate.indexOf("="))
    {
        return false;
    }

    return true;
}

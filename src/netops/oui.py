"""MAC address parsing and vendor lookup against a curated OUI table."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import NetopsError

LOCAL_ADMIN_BIT = 0x02
MULTICAST_BIT = 0x01

#: Curated IEEE OUI prefixes (first three octets, uppercase hex, no separators)
#: covering the vendors most often seen in enterprise, wireless and virtual
#: networking. The table is embedded so lookups work fully offline. Vendor
#: names use the common industry name; a few well-known locally administered
#: conventions (QEMU/KVM, VirtualBox) are included as convenience hints.
VENDOR_PREFIXES: dict[str, str] = {
    # Cisco
    "00000C": "Cisco Systems, Inc.",
    "000142": "Cisco Systems, Inc.",
    "000143": "Cisco Systems, Inc.",
    "001B0C": "Cisco Systems, Inc.",
    "001E13": "Cisco Systems, Inc.",
    "002497": "Cisco Systems, Inc.",
    "00260B": "Cisco Systems, Inc.",
    # Hewlett Packard / Aruba
    "000B86": "Aruba Networks (HPE)",
    "6CF37F": "Aruba Networks (HPE)",
    "84D47E": "Aruba Networks (HPE)",
    "24DEC6": "Aruba Networks (HPE)",
    "001B78": "Hewlett Packard",
    "3CD92B": "Hewlett Packard",
    "000F20": "Hewlett Packard",
    "9457A5": "Hewlett Packard",
    # Juniper
    "000585": "Juniper Networks",
    "0010DB": "Juniper Networks",
    "001BC0": "Juniper Networks",
    "2C6BF5": "Juniper Networks",
    "5C5EAB": "Juniper Networks",
    # Fortinet
    "00090F": "Fortinet, Inc.",
    "085B0E": "Fortinet, Inc.",
    "704CA5": "Fortinet, Inc.",
    # Ubiquiti
    "00156D": "Ubiquiti Networks",
    "245A4C": "Ubiquiti Networks",
    "68D79A": "Ubiquiti Networks",
    "F09FC2": "Ubiquiti Networks",
    "74ACB9": "Ubiquiti Networks",
    # MikroTik
    "000C42": "MikroTik",
    "488F5A": "MikroTik",
    "4C5E0C": "MikroTik",
    "744D28": "MikroTik",
    "2CC81B": "MikroTik",
    # Intel
    "0002B3": "Intel Corporation",
    "000347": "Intel Corporation",
    "001302": "Intel Corporation",
    "001B21": "Intel Corporation",
    "001E67": "Intel Corporation",
    "3CFDFE": "Intel Corporation",
    # VMware
    "000C29": "VMware, Inc.",
    "000569": "VMware, Inc.",
    "001C14": "VMware, Inc.",
    "005056": "VMware, Inc.",
    # Microsoft
    "000D3A": "Microsoft Corporation",
    "00125A": "Microsoft Corporation",
    "00155D": "Microsoft Corporation",
    "0017FA": "Microsoft Corporation",
    "281878": "Microsoft Corporation",
    "7C1E52": "Microsoft Corporation",
    # Dell
    "001422": "Dell Inc.",
    "001EC9": "Dell Inc.",
    "0024E8": "Dell Inc.",
    "180373": "Dell Inc.",
    "B82A72": "Dell Inc.",
    "F8BC12": "Dell Inc.",
    # Apple
    "001B63": "Apple, Inc.",
    "0023DF": "Apple, Inc.",
    "3C0754": "Apple, Inc.",
    "8C8590": "Apple, Inc.",
    "A483E7": "Apple, Inc.",
    "F01898": "Apple, Inc.",
    # Samsung
    "0012FB": "Samsung Electronics Co.,Ltd",
    "001599": "Samsung Electronics Co.,Ltd",
    "002119": "Samsung Electro-Mechanics Co., Ltd.",
    "3C5A37": "Samsung Electronics Co.,Ltd",
    "8C7712": "Samsung Electronics Co.,Ltd",
    # Espressif
    "240AC4": "Espressif Inc.",
    "30AEA4": "Espressif Inc.",
    "84F3EB": "Espressif Inc.",
    "B4E62D": "Espressif Inc.",
    "DC4F22": "Espressif Inc.",
    # Raspberry Pi
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading Ltd",
    "E45F01": "Raspberry Pi Trading Ltd",
    "28CDC1": "Raspberry Pi Trading Ltd",
    # Google
    "3C5AB4": "Google, Inc.",
    "546009": "Google, Inc.",
    "A47733": "Google, Inc.",
    "F4F5D8": "Google, Inc.",
    # Amazon
    "44650D": "Amazon Technologies Inc.",
    "6854FD": "Amazon Technologies Inc.",
    "74C246": "Amazon Technologies Inc.",
    "F0D2F1": "Amazon Technologies Inc.",
    "F02765": "Murata Manufacturing Co., Ltd.",
    # NETGEAR
    "00146C": "NETGEAR",
    "001B2F": "NETGEAR",
    "0024B2": "NETGEAR",
    "204E7F": "NETGEAR",
    "A040A0": "NETGEAR",
    "C03F0E": "NETGEAR",
    # D-Link
    "001B11": "D-Link Corporation",
    "0022B0": "D-Link Corporation",
    "00265A": "D-Link Corporation",
    "1CBDB9": "D-Link International",
    "84C9B2": "D-Link International",
    # TP-Link
    "001D0F": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "002719": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "50C7BF": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "A42BB0": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "C46E1F": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "E894F6": "TP-LINK TECHNOLOGIES CO.,LTD.",
    # Huawei
    "001882": "Huawei Technologies Co.,Ltd",
    "001E10": "Huawei Technologies Co.,Ltd",
    "00259E": "Huawei Technologies Co.,Ltd",
    "286ED4": "Huawei Technologies Co.,Ltd",
    "4C1FCC": "Huawei Technologies Co.,Ltd",
    "E0247F": "Huawei Technologies Co.,Ltd",
    # Arista
    "001C73": "Arista Networks",
    "28993A": "Arista Networks",
    "444CA8": "Arista Networks",
    # Security appliances
    "001B17": "Palo Alto Networks",
    "0001D7": "F5 Networks, Inc.",
    "0023E9": "F5 Networks, Inc.",
    "001C7F": "Check Point Software Technologies",
    "0017C5": "SonicWall",
    "C0EAE4": "SonicWall",
    # Switching and telephony
    "000496": "Extreme Networks",
    "00040D": "Avaya Inc.",
    "001B4F": "Avaya Inc.",
    # Servers and storage
    "000D60": "IBM Corp.",
    "00215E": "IBM Corp.",
    "5CF3FC": "IBM Corp.",
    "00144F": "Oracle Corporation",
    "002128": "Oracle Corporation",
    "0003BA": "Oracle Corporation",
    "00A098": "NetApp",
    "245EBE": "QNAP Systems, Inc.",
    "001132": "Synology Incorporated",
    "9009D0": "Synology Incorporated",
    "0090A9": "Western Digital Technologies, Inc.",
    # Printing and imaging
    "008077": "Brother Industries, LTD.",
    "000085": "Canon Inc.",
    "001E8F": "Canon Inc.",
    # Cameras and IoT
    "00408C": "Axis Communications AB",
    "ACCC8E": "Axis Communications AB",
    "4419B6": "Hangzhou Hikvision Digital Technology Co., Ltd.",
    "4CBD8F": "Hangzhou Hikvision Digital Technology Co., Ltd.",
    "000E58": "Sonos, Inc.",
    "001788": "Philips Lighting BV",
    "ECB5FA": "Philips Lighting BV",
    "18B430": "Nest Labs Inc.",
    # Virtualisation
    "080027": "PCS Systemtechnik GmbH (VirtualBox)",
    "001C42": "Parallels, Inc.",
    "525400": "QEMU/KVM virtual NIC",
    "00163E": "Xensource, Inc. (Xen)",
    # Customer premises equipment
    "001349": "ZyXEL Communications Corporation",
    "0019CB": "ZyXEL Communications Corporation",
    "1C872C": "ASUSTek Computer Inc.",
    "50465D": "ASUSTek Computer Inc.",
    "AC220B": "ASUSTek Computer Inc.",
    "00E04C": "Realtek Semiconductor Corp.",
}


@dataclass(frozen=True)
class MacInfo:
    """Parsed MAC address details."""

    input: str
    normalized: str
    oui: str
    vendor: str | None
    locally_administered: bool
    multicast: bool


def parse_mac(value: str) -> MacInfo:
    """Parse a MAC address or bare OUI in common colon, hyphen, dot or flat form."""
    text = value.strip()
    if not text:
        raise NetopsError("MAC address must not be empty")
    compact = (
        text.replace(":", "")
        .replace("-", "")
        .replace(".", "")
        .replace(" ", "")
        .replace("\t", "")
    )
    if len(compact) not in (6, 12):
        raise NetopsError(
            f"invalid MAC address {value!r}: expected 6 or 12 hexadecimal digits"
        )
    if any(character not in "0123456789abcdefABCDEF" for character in compact):
        raise NetopsError(f"invalid MAC address {value!r}: non-hexadecimal characters found")
    uppercase = compact.upper()
    octets = [uppercase[index : index + 2] for index in range(0, len(uppercase), 2)]
    first_octet = int(octets[0], 16)
    return MacInfo(
        input=text,
        normalized=":".join(octets),
        oui=uppercase[:6],
        vendor=VENDOR_PREFIXES.get(uppercase[:6]),
        locally_administered=bool(first_octet & LOCAL_ADMIN_BIT),
        multicast=bool(first_octet & MULTICAST_BIT),
    )

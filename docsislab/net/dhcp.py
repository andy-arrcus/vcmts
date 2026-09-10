"""DHCP, as DOCSIS uses it.

DOCSIS provisioning leans on three DHCP fields that ordinary DHCP clients
mostly ignore, and they are the reason a modem can find its configuration:

    siaddr  the TFTP server holding the config file
    file    the config file's name
    option 4 / option 2   the Time-of-Day server and time offset

The CMTS sits in the middle as a DHCP relay: it fills in `giaddr` with the
address of the cable interface the request arrived on, which is how the same
DHCP server hands cable modems addresses out of one pool and the CPEs behind
them addresses out of another.  That relay behaviour is `cable helper-address`
on a real CMTS, and it is modelled here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .packet import ip_bytes, ip_str, mac_str

BOOTREQUEST = 1
BOOTREPLY = 2
HTYPE_ETHERNET = 1
MAGIC_COOKIE = bytes([99, 130, 83, 99])

CLIENT_PORT = 68
SERVER_PORT = 67

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)
MSG_NAMES = {DISCOVER: "DISCOVER", OFFER: "OFFER", REQUEST: "REQUEST",
             DECLINE: "DECLINE", ACK: "ACK", NAK: "NAK", RELEASE: "RELEASE",
             INFORM: "INFORM"}

# Options this simulation cares about
OPT_SUBNET_MASK = 1
OPT_TIME_OFFSET = 2
OPT_ROUTER = 3
OPT_TIME_SERVER = 4
OPT_DNS = 6
OPT_LOG_SERVER = 7
OPT_HOSTNAME = 12
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_REQUEST_LIST = 55
OPT_MAX_MSG_SIZE = 57
OPT_RENEWAL_TIME = 58
OPT_REBIND_TIME = 59
OPT_VENDOR_CLASS = 60
OPT_CLIENT_ID = 61
OPT_TFTP_SERVER_NAME = 66
OPT_BOOTFILE_NAME = 67
OPT_RELAY_AGENT_INFO = 82
OPT_END = 255

#: DOCSIS modems identify themselves with this vendor class, which is how a
#: provisioning system tells a modem apart from a CPE on the same relay.
DOCSIS_VENDOR_CLASS = b"docsis2.0:"


@dataclass
class Dhcp:
    """A DHCP message, including the DOCSIS-relevant BOOTP fields."""
    op: int = BOOTREQUEST
    xid: int = 0
    secs: int = 0
    flags: int = 0
    ciaddr: str = "0.0.0.0"
    yiaddr: str = "0.0.0.0"
    siaddr: str = "0.0.0.0"       # next server: the TFTP server, for DOCSIS
    giaddr: str = "0.0.0.0"       # relay agent: the CMTS cable interface
    chaddr: bytes = b"\x00" * 6
    sname: bytes = b""
    file: bytes = b""             # config file name, for DOCSIS
    options: list[tuple[int, bytes]] = field(default_factory=list)

    # -- options ---------------------------------------------------------
    def option(self, code: int) -> bytes | None:
        for c, v in self.options:
            if c == code:
                return v
        return None

    def set_option(self, code: int, value: bytes) -> None:
        self.options = [(c, v) for c, v in self.options if c != code]
        self.options.append((code, value))

    @property
    def msg_type(self) -> int:
        v = self.option(OPT_MSG_TYPE)
        return v[0] if v else 0

    @property
    def msg_name(self) -> str:
        return MSG_NAMES.get(self.msg_type, f"type {self.msg_type}")

    def encode(self) -> bytes:
        out = struct.pack(">BBBBIHH4s4s4s4s", self.op, HTYPE_ETHERNET, 6, 0,
                          self.xid & 0xFFFFFFFF, self.secs, self.flags,
                          ip_bytes(self.ciaddr), ip_bytes(self.yiaddr),
                          ip_bytes(self.siaddr), ip_bytes(self.giaddr))
        out += self.chaddr.ljust(16, b"\x00")
        out += self.sname.ljust(64, b"\x00")
        out += self.file.ljust(128, b"\x00")
        out += MAGIC_COOKIE
        for code, value in self.options:
            out += bytes([code, len(value)]) + value
        out += bytes([OPT_END])
        # BOOTP's minimum body is 300 bytes; some stacks insist on it.
        if len(out) < 300:
            out += b"\x00" * (300 - len(out))
        return out

    def summary(self) -> str:
        bits = [f"DHCP{self.msg_name}", f"xid={self.xid:#010x}",
                f"chaddr={mac_str(self.chaddr[:6])}"]
        if self.yiaddr != "0.0.0.0":
            bits.append(f"yiaddr={self.yiaddr}")
        if self.giaddr != "0.0.0.0":
            bits.append(f"giaddr={self.giaddr}")
        if self.siaddr != "0.0.0.0":
            bits.append(f"siaddr={self.siaddr}")
        if self.file.rstrip(b"\x00"):
            bits.append(f"file={self.file.rstrip(chr(0).encode()).decode(errors='replace')}")
        return " ".join(bits)


def decode(data: bytes) -> Dhcp | None:
    if len(data) < 240:
        return None
    (op, htype, hlen, _hops, xid, secs, flags, ciaddr, yiaddr,
     siaddr, giaddr) = struct.unpack(">BBBBIHH4s4s4s4s", data[:28])
    if htype != HTYPE_ETHERNET:
        return None
    msg = Dhcp(op=op, xid=xid, secs=secs, flags=flags,
               ciaddr=ip_str(ciaddr), yiaddr=ip_str(yiaddr),
               siaddr=ip_str(siaddr), giaddr=ip_str(giaddr),
               chaddr=data[28:28 + max(hlen, 6)],
               sname=data[44:108].rstrip(b"\x00"),
               file=data[108:236].rstrip(b"\x00"))
    if data[236:240] != MAGIC_COOKIE:
        return msg
    i = 240
    while i < len(data):
        code = data[i]
        if code == OPT_END:
            break
        if code == 0:
            i += 1
            continue
        if i + 2 > len(data):
            break
        length = data[i + 1]
        msg.options.append((code, data[i + 2:i + 2 + length]))
        i += 2 + length
    return msg


# --------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------

def discover(xid: int, chaddr: bytes, vendor_class: bytes = DOCSIS_VENDOR_CLASS,
             hostname: str = "") -> Dhcp:
    m = Dhcp(op=BOOTREQUEST, xid=xid, chaddr=chaddr, flags=0x8000)
    m.set_option(OPT_MSG_TYPE, bytes([DISCOVER]))
    m.set_option(OPT_MAX_MSG_SIZE, (1500).to_bytes(2, "big"))
    if vendor_class:
        m.set_option(OPT_VENDOR_CLASS, vendor_class)
    if hostname:
        m.set_option(OPT_HOSTNAME, hostname.encode())
    m.set_option(OPT_PARAM_REQUEST_LIST, bytes([
        OPT_SUBNET_MASK, OPT_TIME_OFFSET, OPT_ROUTER, OPT_TIME_SERVER,
        OPT_DNS, OPT_LOG_SERVER, OPT_LEASE_TIME,
        OPT_TFTP_SERVER_NAME, OPT_BOOTFILE_NAME]))
    return m


def request(xid: int, chaddr: bytes, requested_ip: str, server_id: str,
            vendor_class: bytes = DOCSIS_VENDOR_CLASS) -> Dhcp:
    m = Dhcp(op=BOOTREQUEST, xid=xid, chaddr=chaddr, flags=0x8000)
    m.set_option(OPT_MSG_TYPE, bytes([REQUEST]))
    m.set_option(OPT_REQUESTED_IP, ip_bytes(requested_ip))
    m.set_option(OPT_SERVER_ID, ip_bytes(server_id))
    if vendor_class:
        m.set_option(OPT_VENDOR_CLASS, vendor_class)
    m.set_option(OPT_PARAM_REQUEST_LIST, bytes([
        OPT_SUBNET_MASK, OPT_TIME_OFFSET, OPT_ROUTER, OPT_TIME_SERVER,
        OPT_DNS, OPT_LOG_SERVER, OPT_LEASE_TIME,
        OPT_TFTP_SERVER_NAME, OPT_BOOTFILE_NAME]))
    return m


def reply(request_msg: Dhcp, msg_type: int, yiaddr: str, server_id: str,
          subnet_mask: str, router: str, lease: int = 3600,
          time_server: str | None = None, time_offset: int = 0,
          log_server: str | None = None, dns: str | None = None,
          tftp_server: str | None = None, config_file: str | None = None) -> Dhcp:
    m = Dhcp(op=BOOTREPLY, xid=request_msg.xid, flags=request_msg.flags,
             chaddr=request_msg.chaddr, giaddr=request_msg.giaddr,
             yiaddr=yiaddr)
    m.set_option(OPT_MSG_TYPE, bytes([msg_type]))
    m.set_option(OPT_SERVER_ID, ip_bytes(server_id))
    m.set_option(OPT_SUBNET_MASK, ip_bytes(subnet_mask))
    m.set_option(OPT_ROUTER, ip_bytes(router))
    m.set_option(OPT_LEASE_TIME, lease.to_bytes(4, "big"))
    m.set_option(OPT_RENEWAL_TIME, (lease // 2).to_bytes(4, "big"))
    m.set_option(OPT_REBIND_TIME, (lease * 7 // 8).to_bytes(4, "big"))
    if time_server:
        # A DOCSIS modem must complete Time of Day before it registers, and
        # this is where it learns whom to ask.
        m.set_option(OPT_TIME_SERVER, ip_bytes(time_server))
        m.set_option(OPT_TIME_OFFSET, (time_offset & 0xFFFFFFFF).to_bytes(4, "big"))
    if log_server:
        m.set_option(OPT_LOG_SERVER, ip_bytes(log_server))
    if dns:
        m.set_option(OPT_DNS, ip_bytes(dns))
    if tftp_server:
        # DOCSIS reads the TFTP server from siaddr, and option 66 is set too
        # because some provisioning systems use one and some the other.
        m.siaddr = tftp_server
        m.set_option(OPT_TFTP_SERVER_NAME, tftp_server.encode())
    if config_file:
        m.file = config_file.encode()
        m.set_option(OPT_BOOTFILE_NAME, config_file.encode())
    return m

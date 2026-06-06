from scapy.layers.inet import IP, UDP, TCP
import psutil
<<<<<<< HEAD
from psutil import NoSuchProcess, AccessDenied, ZombieProcess
=======
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9


flags = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
    'N': ''
}


class PacketInfo:
    def __init__(self):
        self.src = ""
        self.dest = ""
        self.src_port = 0
        self.dest_port = 0
        self.protocol = ''
        self.timestamp = 0

        self.PSH_flag = False
        self.FIN_flag = False
        self.SYN_flag = False
        self.ACK_flag = False
        self.URG_flag = False
        self.RST_flag = False

        self.payload_bytes = 0
        self.header_bytes = 0
        self.packet_size = 0
        self.win_bytes = 0

        self.fwd_id = ""
        self.bwd_id = ""

        self.pid = None
        self.p_name = ''

<<<<<<< HEAD
    def _resolve_pid(self):
        """
        Определение PID и имени процесса по локальному порту.
        """
        if self.pid is not None or self.p_name != '':
            return

        try:
            connections = psutil.net_connections(kind='inet')

            for con in connections:
                if not con.laddr:
                    continue

                local_port = con.laddr.port

                if local_port == self.src_port or local_port == self.dest_port:
                    self.pid = con.pid

                    if con.pid is not None:
                        try:
                            self.p_name = psutil.Process(con.pid).name()
                        except (NoSuchProcess, AccessDenied, ZombieProcess):
                            self.p_name = ''

                    break

        except Exception:
            pass
=======
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9

    def setSrc(self, p):
        self.src = p.getlayer(IP).src

    def getSrc(self):
        return self.src

    def setDest(self, p):
        self.dest = p.getlayer(IP).dst

    def getDest(self):
        return self.dest

    def setSrcPort(self, p):
        if p.haslayer(TCP):
            self.src_port = p.getlayer(TCP).sport
<<<<<<< HEAD
        elif p.haslayer(UDP):
            self.src_port = p.getlayer(UDP).sport

        self._resolve_pid()
=======
        if p.haslayer(UDP):
            self.src_port = p.getlayer(UDP).sport

        if self.pid is None and self.p_name == '':
            for con in connections:
                if (con.laddr.port - self.src_port ==0.0) or (con.laddr.port - self.dest_port ==0.0):
                    self.pid = con.pid
                    self.p_name = psutil.Process(con.pid).name()

>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9

    def getSrcPort(self):
        return self.src_port

    def setDestPort(self, p):
        if p.haslayer(TCP):
            self.dest_port = p.getlayer(TCP).dport
<<<<<<< HEAD
        elif p.haslayer(UDP):
            self.dest_port = p.getlayer(UDP).dport

        self._resolve_pid()
=======
        if p.haslayer(UDP):
            self.dest_port = p.getlayer(UDP).dport

        if self.pid is None and self.p_name == '':
            connections = psutil.net_connections()
            for con in connections:
                if (con.laddr.port - self.src_port ==0.0) or (con.laddr.port - self.dest_port ==0.0):
                    self.pid = con.pid
                    self.p_name = psutil.Process(con.pid).name()
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9

    def getPID(self):
        return self.pid

    def getPName(self):
        return self.p_name

    def getDestPort(self):
        return self.dest_port

    def setProtocol(self, p):
        if p.haslayer(TCP):
            self.protocol = 'TCP'
<<<<<<< HEAD
        elif p.haslayer(UDP):
=======
        if p.haslayer(UDP):
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9
            self.protocol = 'UDP'

    def getProtocol(self):
        return self.protocol

    def setTimestamp(self, p):
        self.timestamp = p.time

    def getTimestamp(self):
        return self.timestamp

    def setPSHFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'PSH' in flag:
                self.PSH_flag = True

    def getPSHFlag(self):
        return self.PSH_flag

    def setFINFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'FIN' in flag:
                self.FIN_flag = True

    def getFINFlag(self):
        return self.FIN_flag

    def setSYNFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'SYN' in flag:
                self.SYN_flag = True

    def getSYNFlag(self):
        return self.SYN_flag

    def setACKFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'ACK' in flag:
                self.ACK_flag = True

    def getACKFlag(self):
        return self.ACK_flag

    def setURGFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'URG' in flag:
                self.URG_flag = True

    def getURGFlag(self):
        return self.URG_flag

    def setRSTFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'RST' in flag:
                self.RST_flag = True

    def getRSTFlag(self):
        return self.RST_flag

    def setPayloadBytes(self, p):
        if p.haslayer(TCP):
            self.payload_bytes = len(p[TCP].payload)
<<<<<<< HEAD
        elif p.haslayer(UDP):
=======
        if p.haslayer(UDP):
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9
            self.payload_bytes = len(p[UDP].payload)

    def getPayloadBytes(self):
        return self.payload_bytes

    def setHeaderBytes(self, p):
        if p.haslayer(TCP):
            self.header_bytes = len(p[TCP]) - len(p[TCP].payload)
<<<<<<< HEAD
        elif p.haslayer(UDP):
=======
        if p.haslayer(UDP):
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9
            self.header_bytes = len(p[UDP]) - len(p[UDP].payload)

    def getHeaderBytes(self):
        return self.header_bytes

    def setPacketSize(self, p):
        if p.haslayer(TCP):
            self.packet_size = len(p[TCP])
<<<<<<< HEAD
        elif p.haslayer(UDP):
=======
        if p.haslayer(UDP):
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9
            self.packet_size = len(p[UDP])

    def getPacketSize(self):
        return self.packet_size

    def setWinBytes(self, p):
        if p.haslayer(TCP):
<<<<<<< HEAD
            self.win_bytes = p[TCP].window
=======
            self.win_bytes = p[0].window
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9

    def getWinBytes(self):
        return self.win_bytes

    def setFwdID(self):
<<<<<<< HEAD
        self.fwd_id = (
            self.src + "-" +
            self.dest + "-" +
            str(self.src_port) + "-" +
            str(self.dest_port) + "-" +
            self.protocol
        )
=======
        self.fwd_id = self.src + "-" + self.dest + "-" + \
                       str(self.src_port) + "-" + str(self.dest_port) + "-" + self.protocol
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9

    def getFwdID(self):
        return self.fwd_id

    def setBwdID(self):
<<<<<<< HEAD
        self.bwd_id = (
            self.dest + "-" +
            self.src + "-" +
            str(self.dest_port) + "-" +
            str(self.src_port) + "-" +
            self.protocol
        )
=======
        self.bwd_id = self.dest + "-" + self.src + "-" + \
                      str(self.dest_port) + "-" + str(self.src_port) + "-" + self.protocol
>>>>>>> 218f53b0512bf6c682ac94c45ca9e8fa81e351c9

    def getBwdID(self):
        return self.bwd_id
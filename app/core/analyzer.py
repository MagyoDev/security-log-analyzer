from collections import Counter, defaultdict
from statistics import mean
import ipaddress
import socket

from scapy.all import IP, TCP, UDP, ICMP, DNSQR


COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Alternate",
}

TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


class PacketAnalyzer:
    """
    Classe responsável por analisar pacotes de rede.
    """

    def __init__(self):
        self.hostname_cache = {}
        self.reset()

    def reset(self):
        """
        Limpa todos os contadores.

        Esse método é chamado antes de iniciar uma nova captura.
        """
        self.total_packets = 0

        self.protocols = Counter()
        self.application_protocols = Counter()

        self.source_ips = Counter()
        self.destination_ips = Counter()
        self.destination_ports = Counter()

        self.dns_queries = Counter()
        self.icmp_packets = Counter()

        self.tcp_flags = Counter()
        self.packet_lengths = []

        self.flows = Counter()
        self.directional_flows = Counter()

        self.endpoint_stats = defaultdict(lambda: {"sent": 0, "received": 0})
        self.ports_by_source = defaultdict(set)
        self.syn_ports_by_source = defaultdict(set)

    def resolve_hostname(self, ip: str) -> str:
        """
        Tenta descobrir o hostname/domínio de um IP usando reverse DNS.
        """
        if ip in self.hostname_cache:
            return self.hostname_cache[ip]

        try:
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj.is_private:
                self.hostname_cache[ip] = "local/private"
                return self.hostname_cache[ip]

            if ip_obj.is_loopback:
                self.hostname_cache[ip] = "localhost"
                return self.hostname_cache[ip]

            if ip_obj.is_multicast:
                self.hostname_cache[ip] = "multicast"
                return self.hostname_cache[ip]

            hostname = socket.gethostbyaddr(ip)[0]
            self.hostname_cache[ip] = hostname
            return hostname

        except Exception:
            self.hostname_cache[ip] = "N/A"
            return self.hostname_cache[ip]

    def get_service_name(self, port: int) -> str:
        """
        Retorna o nome comum de uma porta conhecida.
        """
        return COMMON_PORTS.get(port, "Unknown")

    def normalize_flow(self, ip_a: str, ip_b: str) -> tuple:
        """
        Cria uma chave de fluxo ignorando a direção.

        Exemplo:
        192.168.1.2 -> 8.8.8.8
        8.8.8.8 -> 192.168.1.2

        Os dois viram o mesmo fluxo:
        192.168.1.2 <-> 8.8.8.8
        """
        return tuple(sorted([ip_a, ip_b]))

    def classify_packet_length(self, length: int) -> str:
        """
        Classifica o tamanho do pacote em faixas.
        """
        if length <= 99:
            return "0-99 bytes"
        if length <= 499:
            return "100-499 bytes"
        if length <= 999:
            return "500-999 bytes"
        if length <= 1499:
            return "1000-1499 bytes"
        return "1500+ bytes"

    def analyze_packet(self, packet):
        """
        Analisa um pacote capturado pelo Scapy.
        """
        self.total_packets += 1
        self.packet_lengths.append(len(packet))

        if IP not in packet:
            self.protocols["Non-IP"] += 1
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        self.source_ips[src_ip] += 1
        self.destination_ips[dst_ip] += 1

        self.endpoint_stats[src_ip]["sent"] += 1
        self.endpoint_stats[dst_ip]["received"] += 1

        self.flows[self.normalize_flow(src_ip, dst_ip)] += 1
        self.directional_flows[(src_ip, dst_ip)] += 1

        if TCP in packet:
            self._analyze_tcp_packet(packet, src_ip)

        elif UDP in packet:
            self._analyze_udp_packet(packet, src_ip)

        elif ICMP in packet:
            self.protocols["ICMP"] += 1
            self.icmp_packets[src_ip] += 1

        else:
            self.protocols["Other IP"] += 1

        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            self.dns_queries[query] += 1

    def _analyze_tcp_packet(self, packet, src_ip: str):
        """
        Analisa campos específicos de pacotes TCP.
        """
        self.protocols["TCP"] += 1

        dst_port = packet[TCP].dport
        self.destination_ports[(dst_port, "tcp")] += 1
        self.ports_by_source[src_ip].add(dst_port)

        flags = str(packet[TCP].flags)

        for flag in flags:
            if flag in TCP_FLAG_NAMES:
                self.tcp_flags[TCP_FLAG_NAMES[flag]] += 1

        if "S" in flags:
            self.syn_ports_by_source[src_ip].add(dst_port)

        if dst_port == 80:
            self.application_protocols["HTTP"] += 1
        elif dst_port == 443:
            self.application_protocols["HTTPS"] += 1

    def _analyze_udp_packet(self, packet, src_ip: str):
        """
        Analisa campos específicos de pacotes UDP.
        """
        self.protocols["UDP"] += 1

        dst_port = packet[UDP].dport
        self.destination_ports[(dst_port, "udp")] += 1
        self.ports_by_source[src_ip].add(dst_port)

        if dst_port == 53 or packet.haslayer(DNSQR):
            self.application_protocols["DNS"] += 1

    def infer_local_ip(self):
        """
        Tenta descobrir o IP local mais provável.
        """
        candidates = Counter()

        for ip, count in self.source_ips.items():
            try:
                if ipaddress.ip_address(ip).is_private:
                    candidates[ip] += count
            except ValueError:
                continue

        for ip, count in self.destination_ips.items():
            try:
                if ipaddress.ip_address(ip).is_private:
                    candidates[ip] += count
            except ValueError:
                continue

        if not candidates:
            return None

        return candidates.most_common(1)[0][0]

    def get_direction_summary(self, local_ip):
        """
        Calcula tráfego de entrada, saída e interno/outros.
        """
        if not local_ip:
            return {
                "local_ip": None,
                "inbound": 0,
                "outbound": 0,
                "internal_or_other": self.total_packets,
            }

        inbound = 0
        outbound = 0
        internal_or_other = 0

        for (src_ip, dst_ip), count in self.directional_flows.items():
            if dst_ip == local_ip and src_ip != local_ip:
                inbound += count
            elif src_ip == local_ip and dst_ip != local_ip:
                outbound += count
            else:
                internal_or_other += count

        return {
            "local_ip": local_ip,
            "inbound": inbound,
            "outbound": outbound,
            "internal_or_other": internal_or_other,
        }

    def get_packet_length_summary(self):
        """
        Gera resumo dos tamanhos dos pacotes.
        """
        if not self.packet_lengths:
            return {
                "min": 0,
                "max": 0,
                "average": 0,
                "buckets": {},
            }

        buckets = Counter(
            self.classify_packet_length(length)
            for length in self.packet_lengths
        )

        return {
            "min": min(self.packet_lengths),
            "max": max(self.packet_lengths),
            "average": round(mean(self.packet_lengths), 2),
            "buckets": dict(buckets),
        }

    def build_findings(self):
        """
        Cria alertas básicos com base em padrões simples.
        """
        findings = []

        for ip, count in self.source_ips.items():
            if count >= 100:
                findings.append(
                    f"Alto volume de tráfego vindo de {ip}: {count} pacotes"
                )

        for ip, count in self.icmp_packets.items():
            if count >= 20:
                findings.append(
                    f"Alta atividade ICMP vinda de {ip}: {count} pacotes"
                )

        for ip, ports in self.ports_by_source.items():
            if len(ports) >= 10:
                findings.append(
                    f"Possível port scan vindo de {ip}: {len(ports)} portas diferentes"
                )

        for ip, ports in self.syn_ports_by_source.items():
            if len(ports) >= 10:
                findings.append(
                    f"Possível SYN scan vindo de {ip}: SYN para {len(ports)} portas diferentes"
                )

        for domain, count in self.dns_queries.items():
            if count >= 10:
                findings.append(
                    f"Consulta DNS repetida para {domain}: {count} vezes"
                )

        if not findings:
            findings.append("Nenhum alerta detectado.")

        return findings

    def get_risk_level(self, findings):
        """
        Define um nível de risco simples com base nos alertas.
        """
        if not findings or findings == ["Nenhum alerta detectado."]:
            return "Baixo"

        if len(findings) <= 2:
            return "Médio"

        return "Alto"

    def build_report(self):
        """
        Monta o relatório final usado pelo dashboard.
        """
        local_ip = self.infer_local_ip()
        findings = self.build_findings()

        protocols = []

        for protocol, count in self.protocols.most_common():
            percentage = 0

            if self.total_packets > 0:
                percentage = round((count / self.total_packets) * 100, 2)

            protocols.append({
                "protocol": protocol,
                "packets": count,
                "percentage": percentage,
            })

        endpoints = []
        all_ips = set(self.source_ips.keys()) | set(self.destination_ips.keys())

        for ip in all_ips:
            sent = self.endpoint_stats[ip]["sent"]
            received = self.endpoint_stats[ip]["received"]

            endpoints.append({
                "ip": ip,
                "hostname": self.resolve_hostname(ip),
                "sent": sent,
                "received": received,
                "total": sent + received,
            })

        endpoints.sort(key=lambda item: item["total"], reverse=True)

        flows = []

        for (ip_a, ip_b), count in self.flows.most_common(10):
            flows.append({
                "endpoint_a": ip_a,
                "endpoint_b": ip_b,
                "packets": count,
            })

        destination_ports = []

        for (port, protocol), count in self.destination_ports.most_common(10):
            destination_ports.append({
                "port": port,
                "protocol": protocol,
                "service": self.get_service_name(port),
                "packets": count,
            })

        return {
            "total_packets": self.total_packets,
            "risk_level": self.get_risk_level(findings),
            "direction_summary": self.get_direction_summary(local_ip),
            "protocols": protocols,
            "application_protocols": dict(self.application_protocols),
            "endpoints": endpoints[:10],
            "flows": flows,
            "destination_ports": destination_ports,
            "dns_queries": dict(self.dns_queries.most_common(10)),
            "tcp_flags": dict(self.tcp_flags),
            "packet_lengths": self.get_packet_length_summary(),
            "findings": findings,
        }
    
    
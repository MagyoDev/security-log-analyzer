from datetime import datetime
from threading import Lock

class AppState:
    """
    Guarda o estado atual da aplicação.

    Memória temporária.
    Ela armazena se a captura está rodando, quando começou,
    quantos pacotes foram capturados e qual é o último relatório disponível.
    """

    def __init__(self):
        self.lock = Lock()
        self.is_capturing = False
        self.capture_mode = "fixed"
        self.packet_limit = 100
        self.started_at = None
        self.stopped_at = None
        self.report = self._empty_report()

    def _empty_report(self):
        """
        Cria um relatório vazio.
        """
        return {
            "total_packets": 0,
            "risk_level": "Baixo",
            "direction_summary": {
                "local_ip": None,
                "inbound": 0,
                "outbound": 0,
                "internal_or_other": 0
            },
            "protocols": [],
            "application_protocols": {},
            "endpoints": [],
            "flows": [],
            "destination_ports": [],
            "dns_queries": {},
            "tcp_flags": {},
            "packet_lengths": {
                "min": 0,
                "max": 0,
                "average": 0,
                "buckets": {},
            },
            "findings": [
                "Nenhuma alerta detectada."
            ],
        }
    
    def start_capture(self, mode: str, packet_limit: int):
        """
        Marca o início da captura de pacotes.
        """
        with self.lock:
            self.is_capturing = True
            self.capture_mode = mode
            self.packet_limit = packet_limit
            self.started_at = datetime.now().isoformat(timespec='seconds')
            self.stopped_at = None
            self.report = self._empty_report()

    def stop_capture(self):
        """
        Marca o fim da captura de pacotes.
        """
        with self.lock:
            self.is_capturing = False
            self.stopped_at = datetime.now().isoformat(timespec='seconds')

    def reset(self):
        """
        Reseta o estado da aplicação.
        """
        with self.lock:
            self.is_capturing = False
            self.capture_mode = "fixed"
            self.packet_limit = 100
            self.started_at = None
            self.stopped_at = None
            self.report = self._empty_report()

    def update_report(self, report: dict):
        """
        Atualiza o relatório armazenado.
        """
        with self.lock:
            self.report = report

    def get_snapshot(self):
        """
        Retorna uma cópia do estado atual da aplicação.
        """
        with self.lock:
            return {
                "is_capturing": self.is_capturing,
                "capture_mode": self.capture_mode,
                "packet_limit": self.packet_limit,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "report": self.report,
            }
        
app_state = AppState()
from datetime import datetime
from threading import Lock
from uuid import uuid4


class AppState:
    """
    Essa classe funciona como uma memória temporária do sistema.
    Ela armazena o estado da captura atual, o último relatório
    e um histórico simples das capturas realizadas.
    """
    def __init__(self):
        self.lock = Lock()
        self.history_limit = 20
        self.history = []
        self.reset()

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
                "internal_or_other": 0,
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
                "Nenhum alerta detectado."
            ],
        }

    def _create_capture_id(self):
        """
        Cria um ID curto para identificar uma captura.
        """
        return str(uuid4())[:8]

    def _build_history_item(self):
        """
        Cria um item resumido para o histórico.
        """
        return {
            "capture_id": self.capture_id,
            "status": self.status,
            "capture_mode": self.capture_mode,
            "packet_limit": self.packet_limit,
            "iface": self.iface,
            "protocol_filter": self.protocol_filter,
            "host_filter": self.host_filter,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "error_message": self.error_message,
            "total_packets": self.report["total_packets"],
            "risk_level": self.report["risk_level"],
            "report": self.report,
        }

    def _save_to_history(self):
        """
        Salva a captura atual no histórico.
        """
        if self.current_capture_saved:
            return

        history_item = self._build_history_item()

        self.history.insert(0, history_item)
        self.history = self.history[:self.history_limit]

        self.current_capture_saved = True

    def start_capture(
        self,
        mode: str,
        packet_limit: int,
        iface: str | None = None,
        protocol_filter: str | None = None,
        host_filter: str | None = None,
    ):
        """
        Marca a captura como iniciada.
        """
        with self.lock:
            self.capture_id = self._create_capture_id()
            self.current_capture_saved = False
            self.is_capturing = True
            self.status = "capturing"
            self.capture_mode = mode
            self.packet_limit = packet_limit
            self.iface = iface
            self.protocol_filter = protocol_filter
            self.host_filter = host_filter
            self.started_at = datetime.now().isoformat(timespec="seconds")
            self.stopped_at = None
            self.error_message = None
            self.report = self._empty_report()

    def finish_capture(self, report: dict):
        """
        Finaliza uma captura com sucesso.
        """
        with self.lock:
            self.report = report
            self.is_capturing = False
            self.status = "completed"
            self.stopped_at = datetime.now().isoformat(timespec="seconds")
            self.error_message = None
            self._save_to_history()

    def fail_capture(self, report: dict, message: str):
        """
        Finaliza uma captura com erro.
        """
        with self.lock:
            self.report = report
            self.is_capturing = False
            self.status = "error"
            self.error_message = message
            self.stopped_at = datetime.now().isoformat(timespec="seconds")
            self._save_to_history()

    def stop_capture(self):
        """
        Mantido por compatibilidade.
        A finalização real deve ser feita com finish_capture().
        """
        with self.lock:
            self.is_capturing = False
            self.status = "completed"
            self.stopped_at = datetime.now().isoformat(timespec="seconds")

    def set_error(self, message: str):
        """
        Mantido por compatibilidade.
        Erros de captura devem usar fail_capture().
        """
        with self.lock:
            self.is_capturing = False
            self.status = "error"
            self.error_message = message
            self.stopped_at = datetime.now().isoformat(timespec="seconds")

    def reset(self):
        """
        Reseta apenas a captura atual.
        """
        with self.lock:
            self.capture_id = None
            self.current_capture_saved = False
            self.is_capturing = False
            self.status = "idle"
            self.capture_mode = "fixed"
            self.packet_limit = 100
            self.iface = None
            self.protocol_filter = None
            self.host_filter = None
            self.started_at = None
            self.stopped_at = None
            self.error_message = None
            self.report = self._empty_report()

    def clear_history(self):
        """
        Limpa o histórico de capturas.
        """
        with self.lock:
            self.history = []

    def update_report(self, report: dict):
        """
        Atualiza o relatório atual sem finalizar a captura.
        """
        with self.lock:
            self.report = report

    def get_snapshot(self):
        """
        Retorna uma cópia do estado atual da aplicação.
        """
        with self.lock:
            return {
                "capture_id": self.capture_id,
                "is_capturing": self.is_capturing,
                "status": self.status,
                "capture_mode": self.capture_mode,
                "packet_limit": self.packet_limit,
                "iface": self.iface,
                "protocol_filter": self.protocol_filter,
                "host_filter": self.host_filter,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "error_message": self.error_message,
                "report": self.report,
                "history": self._get_history_summary(),
            }

    def _get_history_summary(self):
        """
        Retorna uma versão resumida do histórico.
        """
        return [
            {
                "capture_id": item["capture_id"],
                "status": item["status"],
                "capture_mode": item["capture_mode"],
                "packet_limit": item["packet_limit"],
                "iface": item["iface"],
                "protocol_filter": item["protocol_filter"],
                "host_filter": item["host_filter"],
                "started_at": item["started_at"],
                "stopped_at": item["stopped_at"],
                "total_packets": item["total_packets"],
                "risk_level": item["risk_level"],
                "error_message": item["error_message"],
            }
            for item in self.history
        ]

    def get_history(self):
        """
        Retorna o histórico resumido.
        """
        with self.lock:
            return self._get_history_summary()

    def get_history_report(self, capture_id: str):
        """
        Retorna o relatório completo de uma captura específica.
        """
        with self.lock:
            for item in self.history:
                if item["capture_id"] == capture_id:
                    return item["report"]

        return None


app_state = AppState()
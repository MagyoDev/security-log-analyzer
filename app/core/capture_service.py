from threading import Event, Thread

from scapy.all import sniff

from app.core.analyzer import PacketAnalyzer
from app.core.state import app_state


class CaptureService:
    """
    Serviço responsável por controlar a captura de pacotes.
    """

    def __init__(self):
        self.analyzer = PacketAnalyzer()
        self.stop_event = Event()
        self.capture_thread = None

    def start_capture(
        self,
        mode: str,
        packet_limit: int,
        iface: str | None = None,
        protocol_filter: str | None = None,
        host_filter: str | None = None,
    ):
        """
        Inicia uma captura de pacotes.
        """
        snapshot = app_state.get_snapshot()

        if snapshot["is_capturing"]:
            return {
                "started": False,
                "message": "Capture is already running",
            }

        if mode not in ["fixed", "continuous"]:
            return {
                "started": False,
                "message": "Invalid capture mode",
            }

        bpf_filter = self._build_bpf_filter(
            protocol_filter=protocol_filter,
            host_filter=host_filter,
        )

        self.analyzer.reset()
        self.stop_event.clear()

        app_state.start_capture(
            mode=mode,
            packet_limit=packet_limit,
            iface=iface,
            protocol_filter=protocol_filter,
            host_filter=host_filter,
        )

        if mode == "continuous":
            count = 0
        else:
            count = packet_limit

        self.capture_thread = Thread(
            target=self._capture_worker,
            args=(count, iface, bpf_filter),
            daemon=True,
        )

        self.capture_thread.start()

        return {
            "started": True,
            "message": "Capture started",
        }

    def stop_capture(self):
        """
        Solicita a parada da captura.
        """
        snapshot = app_state.get_snapshot()

        if not snapshot["is_capturing"]:
            return {
                "stopped": False,
                "message": "No capture is running",
            }

        self.stop_event.set()

        report = self.analyzer.build_report()
        app_state.finish_capture(report)

        return {
            "stopped": True,
            "message": "Capture stopped",
        }

    def _build_bpf_filter(
        self,
        protocol_filter: str | None,
        host_filter: str | None,
    ) -> str | None:
        """
        Monta um filtro BPF para o Scapy.
        """
        filters = []

        if protocol_filter:
            if protocol_filter == "tcp":
                filters.append("tcp")
            elif protocol_filter == "udp":
                filters.append("udp")
            elif protocol_filter == "icmp":
                filters.append("icmp")
            elif protocol_filter == "dns":
                filters.append("port 53")
            elif protocol_filter == "http":
                filters.append("tcp port 80")
            elif protocol_filter == "https":
                filters.append("tcp port 443")

        if host_filter:
            filters.append(f"host {host_filter}")

        if not filters:
            return None

        return " and ".join(filters)

    def _capture_worker(self, count: int, iface: str | None, bpf_filter: str | None):
        """
        Executa o sniff do Scapy e atualiza o relatório ao terminar.
        """
        had_error = False

        try:
            sniff(
                prn=self._handle_packet,
                count=count,
                iface=iface,
                filter=bpf_filter,
                store=False,
                stop_filter=self._should_stop,
            )

        except PermissionError:
            had_error = True
            self._set_error_report(
                "Permissão negada. Execute o programa como administrador/root."
            )

        except Exception as error:
            had_error = True
            self._set_error_report(
                f"Erro durante a captura: {error}"
            )

        finally:
            if not had_error:
                snapshot = app_state.get_snapshot()

                if snapshot["is_capturing"]:
                    report = self.analyzer.build_report()
                    app_state.finish_capture(report)

    def _handle_packet(self, packet):
        """
        Recebe cada pacote capturado e envia para o analisador.
        """
        self.analyzer.analyze_packet(packet)

        report = self.analyzer.build_report()
        app_state.update_report(report)

    def _should_stop(self, packet):
        """
        Diz ao Scapy quando parar a captura.
        """
        return self.stop_event.is_set()

    def _set_error_report(self, message: str):
        """
        Atualiza o relatório com mensagem de erro.
        """
        report = self.analyzer.build_report()
        report["risk_level"] = "Erro"
        report["findings"] = [message]

        app_state.fail_capture(report, message)


capture_service = CaptureService()
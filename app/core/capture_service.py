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

    def start_capture(self, mode: str, packet_limit: int, iface: str | None = None):
        """
        Inicia uma captura de pacotes.

        mode:
            fixed      -> captura uma quantidade definida
            continuous -> captura até o usuário parar

        packet_limit:
            quantidade de pacotes no modo fixed

        iface:
            interface de rede, opcional
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

        self.analyzer.reset()
        self.stop_event.clear()

        app_state.start_capture(mode=mode, packet_limit=packet_limit)

        if mode == "continuous":
            count = 0
        else:
            count = packet_limit

        self.capture_thread = Thread(
            target=self._capture_worker,
            args=(count, iface),
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
        app_state.update_report(report)
        app_state.stop_capture()

        return {
            "stopped": True,
            "message": "Capture stopped",
        }

    def _capture_worker(self, count: int, iface: str | None):
        """
        Ela executa o sniff do Scapy e atualiza o relatório ao terminar.
        """
        had_error = False

        try:
            sniff(
                prn=self._handle_packet,
                count=count,
                iface=iface,
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
                report = self.analyzer.build_report()
                app_state.update_report(report)
                app_state.stop_capture()

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

        app_state.update_report(report)
        app_state.set_error(message)


capture_service = CaptureService()
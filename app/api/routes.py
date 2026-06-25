from fastapi import APIRouter
from fastapi.responses import FileResponse
from scapy.all import get_if_list

from app.core.capture_service import capture_service
from app.core.exporters import (
    export_report_csv_zip,
    export_report_excel,
    export_report_json,
    export_report_markdown,
)
from app.core.state import app_state
from app.schemas.capture import CaptureRequest


router = APIRouter(prefix="/api")

@router.get("/status")
def get_status():
    """
    Retorna o estado atual da aplicação.
    """
    return app_state.get_snapshot()

@router.get("/report")
def get_report():
    """
    Retorna apenas o relatório atual.
    """
    snapshot = app_state.get_snapshot()
    return snapshot["report"]

@router.post("/start")
def start_capture(request: CaptureRequest):
    """
    Inicia uma captura real de pacotes.
    """
    result = capture_service.start_capture(
        mode=request.mode,
        packet_limit=request.packet_limit,
        iface=request.iface,
        protocol_filter=request.protocol_filter,
        host_filter=request.host_filter,
    )

    return {
        "message": result["message"],
        "state": app_state.get_snapshot(),
    }

@router.post("/stop")
def stop_capture():
    """
    Para a captura em andamento.
    """
    result = capture_service.stop_capture()

    return {
        "message": result["message"],
        "state": app_state.get_snapshot(),
    }

@router.post("/reset")
def reset_state():
    """
    Reseta o estado da aplicação.
    """
    app_state.reset()

    return {
        "message": "State reset",
        "state": app_state.get_snapshot(),
    }

@router.get("/interfaces")
def get_interfaces():
    """
    Retorna as interfaces de rede disponíveis para captura.
    """
    interfaces = get_if_list()

    return {
        "interfaces": interfaces
    }

@router.get("/history")
def get_history():
    """
    Retorna o histórico resumido das capturas.
    """
    return {
        "history": app_state.get_history()
    }


@router.get("/history/{capture_id}")
def get_history_report(capture_id: str):
    """
    Retorna o relatório completo de uma captura do histórico.
    """
    report = app_state.get_history_report(capture_id)

    if report is None:
        return {
            "error": "Capture not found"
        }

    return report


@router.post("/history/clear")
def clear_history():
    """
    Limpa o histórico de capturas.
    """
    app_state.clear_history()

    return {
        "message": "History cleared",
        "history": app_state.get_history()
    }

@router.get("/export/json")
def export_json():
    """
    Exporta o relatório atual em JSON.
    """
    snapshot = app_state.get_snapshot()
    report = snapshot["report"]

    file_path = export_report_json(report)

    return FileResponse(
        path=file_path,
        filename=file_path.name,
        media_type="application/json",
    )


@router.get("/export/markdown")
def export_markdown():
    """
    Exporta o relatório atual em Markdown.
    """
    snapshot = app_state.get_snapshot()
    report = snapshot["report"]

    file_path = export_report_markdown(report)

    return FileResponse(
        path=file_path,
        filename=file_path.name,
        media_type="text/markdown",
    )

@router.get("/export/excel")
def export_excel():
    """
    Exporta o relatório atual em Excel.
    """
    snapshot = app_state.get_snapshot()
    report = snapshot["report"]

    file_path = export_report_excel(report)

    return FileResponse(
        path=file_path,
        filename=file_path.name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

@router.get("/export/csv")
def export_csv():
    """
    Exporta o relatório atual em CSV compactado.
    """
    snapshot = app_state.get_snapshot()
    report = snapshot["report"]

    file_path = export_report_csv_zip(report)

    return FileResponse(
        path=file_path,
        filename=file_path.name,
        media_type="application/zip",
    )


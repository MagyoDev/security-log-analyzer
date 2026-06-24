from fastapi import APIRouter
from fastapi.responses import FileResponse

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
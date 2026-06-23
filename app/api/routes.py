from fastapi import APIRouter

from app.core.capture_service import capture_service
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
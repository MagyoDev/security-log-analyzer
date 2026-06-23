from fastapi import APIRouter

from app.core.state import app_state

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
def start_capture():
    """
    Captura simulada - TESTANDO mudança de estado da aplicação.
    """
    app_state.start_capture(mode="fixed", packet_limit=100)

    return {
        "message": "Capture started",
        "state": app_state.get_snapshot(),
    }

@router.post("/stop")
def stop_capture():
    """
    Para a captura simulada.
    """
    app_state.stop_capture()

    return {
        "message": "Capture stopped",
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
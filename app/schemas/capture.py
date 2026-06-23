from pydantic import BaseModel, Field


class CaptureRequest(BaseModel):
    """
    Modelo dos dados enviados pela interface ao iniciar captura.
    """

    mode: str = Field(default="fixed")
    packet_limit: int = Field(default=100, ge=1, le=10000)
    iface: str | None = None
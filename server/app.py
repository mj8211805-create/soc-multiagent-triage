"""FastAPI Application instance and WebSocket setup."""

from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from config import settings
from server.routes import router


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Autonomous Multi-Agent System for SOC Malware Triage and Alert Correlation"
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API Router
    app.include_router(router)

    # Mount Static Files
    static_dir = Path(__file__).resolve().parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/")
    async def serve_index():
        index_path = static_dir / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        return {"message": "AegisSOC API is running. Web UI not found in static directory."}

    # WebSocket connection manager
    active_websockets = set()

    @app.websocket("/ws/live")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        active_websockets.add(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                # Broadcast or echo heartbeat
                await websocket.send_json({"event": "PONG", "received": data})
        except WebSocketDisconnect:
            active_websockets.remove(websocket)

    return app


app = create_app()

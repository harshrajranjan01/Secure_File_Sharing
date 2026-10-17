from fastapi import FastAPI
from backend.api.routes import health, files
app = FastAPI()

app.include_router(health.router)
app.include_router(files.router)

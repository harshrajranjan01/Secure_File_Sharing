from fastapi import FastAPI
from backend.api.routes import health, files,auth
app = FastAPI()

app.include_router(health.router)
app.include_router(files.router)
app.include_router(auth.router)

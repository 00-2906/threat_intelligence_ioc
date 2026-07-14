from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import init_db
from app.routers import history, scan

BANNER = r"""
   _____ ____   ______   _____                  
  |_   _/ __ \ / ____/  / ____|                 
    | || |  | | |      | (___   ___ __ _ _ __   
    | || |  | | |       \___ \ / __/ _` | '_ \  
   _| || |__| | |____   ____) | (_| (_| | | | | 
  |_____\____/ \_____| |_____/ \___\__,_|_| |_| 

  🕵️  Your friendly neighborhood threat sniffer is booting up...
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(BANNER)
    init_db()
    print("  📁 scans.db ready — every scan gets remembered.\n")
    yield


app = FastAPI(
    title="IOC Scanner API",
    description="AI-powered threat intelligence IOC scanner",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(scan.router, tags=["scan"])
app.include_router(history.router, tags=["history"])


@app.get("/health")
def health_check():
    return {"status": "ok", "vibe": "😎 all systems chill"}

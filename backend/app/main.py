from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.db import init_db
from app.routers import history, scan, log_scan, summarize


BANNER = r"""
   _____ ____   ______   _____                  
  |_   _/ __ \ / ____/  / ____|                 
    | || |  | | |      | (___   ___ __ _ _ __   
    | || |  | | |       \___ \ / __/ _` | '_ \  
   _| || |__| | |____   ____) | (_| (_| | | | | 
  |_____\____/ \_____| |_____/ \___\__,_|_| |_| 

  [IOC Scanner] Your friendly neighborhood threat sniffer is booting up...
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(BANNER)
    init_db()
    print("  [DATABASE] Ready to store scan results\n")
    yield


app = FastAPI(
    title="IOC Scanner API",
    description="AI-powered threat intelligence IOC scanner",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your deployed frontend URL once it's live
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router, tags=["scan"])
app.include_router(history.router, tags=["history"])
app.include_router(log_scan.router, prefix="/api/logs", tags=["log-scan"])


@app.get("/health")
def health_check():
    return {"status": "ok", "vibe": "all systems operational"}
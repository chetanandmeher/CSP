from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.routes.attackers import router as attackers_router

from backend.app.routes.attack_techniques import (
    router as attack_techniques_router
)
from backend.app.routes.attack_tactics import (
    router as attack_tactics_router
)

from backend.app.routes.mitre import (
    router as mitre_router
)

app = FastAPI(
    title="CSP Threat Intelligence Platform",
    version="1.0.0"
)

app.include_router(
    mitre_router,
    prefix="/mitre",
    tags=["MITRE ATT&CK"]
)

app.add_middleware(
    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)

app.include_router(
    attackers_router,
    prefix="/attackers",
    tags=["Attackers"]
)

app.include_router(
    attack_techniques_router,
    prefix="/attack-techniques",
    tags=["ATT&CK Techniques"]
)

app.include_router(
    attack_tactics_router,
    prefix="/attack-tactics",
    tags=["ATT&CK Tactics"]
)


@app.get("/")
def root():

    return {
        "message":
        "CSP Threat Intelligence Platform Running"
    }   
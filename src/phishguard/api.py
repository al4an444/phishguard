"""REST API. Run with ``uvicorn phishguard.api:app``."""

from __future__ import annotations

from importlib import resources
from typing import Annotated, Literal

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from phishguard import __version__
from phishguard.analyzer import analyze_url
from phishguard.email_analyzer import MAX_EMAIL_BYTES, InvalidEmailError, analyze_email
from phishguard.features import MAX_URL_LENGTH, InvalidURLError
from phishguard.ml import model_info

MAX_BATCH_SIZE = 100

app = FastAPI(
    title="PhishGuard",
    version=__version__,
    description="Detección de phishing explicable para URLs y correos. "
                "El análisis es local: nunca se visitan las URLs.",
)


UrlStr = Annotated[str, Field(min_length=1, max_length=MAX_URL_LENGTH)]
Verdict = Literal["low_risk", "suspicious", "phishing"]


class AnalyzeRequest(BaseModel):
    url: UrlStr = Field(..., examples=["http://paypa1-login.xyz/verify"])


class BatchRequest(BaseModel):
    urls: list[UrlStr] = Field(..., min_length=1, max_length=MAX_BATCH_SIZE)


class EmailRequest(BaseModel):
    raw: str = Field(..., min_length=1, max_length=MAX_EMAIL_BYTES,
                     description="Mensaje completo en formato RFC 822 (.eml), con cabeceras.")


class FindingOut(BaseModel):
    rule: str
    weight: int
    message: str
    evidence: str


class ReportOut(BaseModel):
    url: str
    normalized_url: str
    host: str
    registered_domain: str
    score: int = Field(..., ge=0, le=100)
    verdict: Verdict
    ml_probability: float | None = None
    findings: list[FindingOut]


class BatchItem(BaseModel):
    url: str
    report: ReportOut | None = None
    error: str | None = None


class EmailLinkOut(BaseModel):
    url: str
    text: str
    report: ReportOut


class EmailReportOut(BaseModel):
    subject: str
    sender: str
    sender_domain: str
    score: int = Field(..., ge=0, le=100)
    verdict: Verdict
    findings: list[FindingOut]
    links: list[EmailLinkOut]
    attachments: list[str]


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> str:
    return resources.files("phishguard").joinpath("static/index.html").read_text(encoding="utf-8")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "ml_model": model_info() is not None}


@app.get("/model")
def model() -> dict:
    """Metadatos y métricas de evaluación del modelo de ML incluido."""
    info = model_info()
    if info is None:
        raise HTTPException(status_code=404, detail="no hay un modelo entrenado")
    return info


@app.post("/analyze", response_model=ReportOut)
def analyze(request: AnalyzeRequest) -> dict:
    try:
        return analyze_url(request.url).to_dict()
    except InvalidURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/analyze/batch", response_model=list[BatchItem])
def analyze_batch(request: BatchRequest) -> list[dict]:
    items = []
    for url in request.urls:
        try:
            items.append({"url": url, "report": analyze_url(url).to_dict()})
        except InvalidURLError as exc:
            items.append({"url": url, "error": str(exc)})
    return items


def _email_response(data: bytes | str) -> dict:
    try:
        return analyze_email(data).to_dict()
    except InvalidEmailError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/analyze/email", response_model=EmailReportOut)
def analyze_email_text(request: EmailRequest) -> dict:
    return _email_response(request.raw)


@app.post("/analyze/email/upload", response_model=EmailReportOut)
async def analyze_email_upload(file: Annotated[UploadFile, File(description="Archivo .eml")]) -> dict:
    data = await file.read(MAX_EMAIL_BYTES + 1)
    if len(data) > MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="el archivo supera el tamaño máximo")
    return _email_response(data)

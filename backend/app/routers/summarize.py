from fastapi import APIRouter, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
from app.services.summarizer import summarize_text

router = APIRouter()


@router.post("/api/summarize")
async def summarize(file: UploadFile, chunk_lines: int = Form(250), overlap_lines: int = Form(5)):
    if not file:
        raise HTTPException(status_code=400, detail="no file provided")
    data = await file.read()
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = str(data)
    result = summarize_text(text, chunk_size=chunk_lines, overlap=overlap_lines)
    return JSONResponse(result)

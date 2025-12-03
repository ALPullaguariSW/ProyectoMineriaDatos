import sys
import os

# Add current directory to sys.path to allow imports from src
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
import uvicorn
import shutil
import tempfile
from predict import load_model, predict_file

app = FastAPI(
    title="Vulnerability Detection API",
    description="API for detecting vulnerabilities in source code using Data Mining models.",
    version="1.0.0"
)

# Load model on startup
model, vectorizer = load_model()

class PredictionResult(BaseModel):
    filename: str
    status: str
    confidence: float
    details: dict
    message: str

@app.get("/")
def read_root():
    return {"message": "Vulnerability Detection API is running. Use /scan to check files."}

@app.post("/scan", response_model=PredictionResult)
async def scan_file(file: UploadFile = File(...)):
    """
    Scans an uploaded file for vulnerabilities.
    """
    try:
        # Save temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name
            
        # Predict
        pred, prob, details = predict_file(tmp_path, model, vectorizer)
        
        # Cleanup
        os.unlink(tmp_path)
        
        status = "VULNERABLE" if pred == 1 else "SAFE"
        
        return {
            "filename": file.filename,
            "status": status,
            "confidence": float(prob),
            "details": details,
            "message": f"File is {status} with {prob:.2f} confidence."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
import shutil
import os
import sys

# Import local modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.model.predict import load_model, predict_file

app = FastAPI(
    title="SecureCode AI Scanner",
    description="API for detecting vulnerabilities in source code using Data Mining (Random Forest).",
    version="1.0.0"
)

# Load Model Once
try:
    model, vectorizer = load_model()
    print("✅ Model loaded successfully.")
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    model, vectorizer = None, None

class ScanResponse(BaseModel):
    filename: str
    status: str
    confidence: float
    details: dict

@app.get("/")
def home():
    return {"message": "SecureCode AI Scanner is Live! 🚀", "docs": "/docs"}

@app.post("/scan", response_model=ScanResponse)
async def scan_code(file: UploadFile = File(...)):
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded.")
    
    # Save temp file
    temp_filename = f"temp_{file.filename}"
    with open(temp_filename, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        # Predict
        pred, prob, details = predict_file(temp_filename, model, vectorizer)
        status = "VULNERABLE" if pred == 1 else "SAFE"
        
        return {
            "filename": file.filename,
            "status": status,
            "confidence": float(prob),
            "details": details
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Cleanup
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import threading
from backend import sniffer, auth, db
import time

app = FastAPI()

# Allow requests from the React Frontend
origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Auth Routes
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])

@app.on_event("startup")
def startup_event():
    """Start the background packet sniffer and initialize DB when the API starts."""
    sniffer.start_sniffer()
    try:
        db.init_db()
    except Exception as e:
        print(f"Database init failed: {e}")

@app.get("/")
def read_root():
    return {"message": "Visual Security Analytics API is running"}

@app.get("/stats")
def get_stats():
    """Returns real-time aggregated statistics for KPI cards."""
    return sniffer.get_stats()

@app.get("/traffic")
def get_traffic():
    """Returns recent packet data for the main graph."""
    # Convert timestamps to string for JSON serialization
    log = sniffer.get_packet_log()
    # Return last 50 packets for smooth graphing
    recent_log = log[-50:] 
    
    # Format for frontend
    formatted_log = []
    for packet in recent_log:
        formatted_log.append({
            "time": packet["Timestamp"].strftime("%H:%M:%S"),
            "packets": 1, # Represents 1 packet event for now
            "protocol": packet["Protocol"],
            "length": packet["Length"]
        })
    return formatted_log

@app.get("/alerts")
def get_alerts():
    """Returns security alerts."""
    stats = sniffer.get_stats()
    return stats["alerts"]

@app.get("/analytics")
def get_analytics():
    """Returns detailed analytics for the Traffic Analytics page."""
    return sniffer.get_analytics()

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Uploads a file for processing in a background thread."""
    contents = await file.read()
    filename = file.filename
    
    # Run processing effectively in background (or thread pool)
    # Since parsing 1M packets is CPU bound, we shouldn't block the async loop
    # We'll use a thread logic inside sniffer or just run it here
    
    def process_task():
        sniffer.process_imported_file(contents, filename)

    # Start processing in background
    thread = threading.Thread(target=process_task)
    thread.start()
    
    return {"message": "File upload started. Processing in background...", "status": "processing"}

@app.post("/clear_import")
def clear_import():
    """Clears imported data to resume live monitoring."""
    return sniffer.clear_imported_data()

@app.get("/anomalies")
def get_anomalies():
    """Returns anomaly statistics."""
    # Assuming this exists in sniffer.py based on previous context, even if not fully visible
    return sniffer.get_anomaly_stats()

class AnomalyFixRequest(BaseModel):
    source_ip: str
    anomaly_type: str

@app.post("/anomalies/fix")
def fix_anomaly(req: AnomalyFixRequest):
    """Applies a fix/mitigation for a reported anomaly."""
    return sniffer.resolve_anomaly(req.source_ip, req.anomaly_type)
    return sniffer.get_anomaly_stats()

@app.get("/forensics")
def get_forensics():
    """Returns forensic investigation data."""
    return sniffer.get_forensic_stats()

@app.get("/report")
def get_report():
    """Returns aggregated data for the full security report."""
    return sniffer.get_full_report_stats()

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)

"""
CyberSentinel Pro v1.0 — Backend FastAPI
Auteur : Prof. M. TONI
"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sklearn.ensemble import IsolationForest
import nmap
import pandas as pd
import numpy as np
import os
from pathlib import Path

app = FastAPI(title="CyberSentinel Pro", version="1.0")

# CORS — autoriser le frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Initialisation du modèle IA ───────────────────────────────────────────
# Entraînement sur un jeu de données "trafic normal" synthétique
np.random.seed(42)
normal_data = pd.DataFrame({
    "packet_count": np.random.randint(100, 2000, 500),
    "size":         np.random.randint(64,  1500,  500),
    "duration":     np.random.randint(5,   120,   500),
})
model_ia = IsolationForest(contamination=0.1, random_state=42)
model_ia.fit(normal_data)
print("[IA] Modèle Isolation Forest entraîné sur 500 échantillons normaux.")

# ─── Route principale — Frontend ────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def frontend():
    html_path = Path(__file__).parent / "templates" / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>CyberSentinel Pro — Frontend introuvable</h1>", status_code=404)

# ─── Analyse IA ─────────────────────────────────────────────────────────────
@app.post("/api/v1/analyze")
async def analyze_traffic(data: dict):
    """
    Analyse comportementale par Isolation Forest.
    Données attendues : packet_count, size, duration
    """
    try:
        features = pd.DataFrame([{
            "packet_count": data.get("packet_count", 0),
            "size":         data.get("size", 0),
            "duration":     data.get("duration", 1),
        }])
        prediction = model_ia.predict(features)
        score      = model_ia.score_samples(features)[0]
        # score négatif proche de 0 = anomalie
        confidence = float(min(abs(score) * 2, 0.99))
        status = "CLEAN" if prediction[0] == 1 else "THREAT_DETECTED"
        return {
            "analysis_id": f"cs-{abs(hash(str(data)))%99999:05d}",
            "status":      status,
            "confidence":  round(confidence, 3),
            "score":       round(float(score), 4),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ─── Scan réseau ─────────────────────────────────────────────────────────────
@app.get("/api/v1/scan/{target}")
async def network_scan(target: str, args: str = "-F"):
    """
    Scan de ports via python-nmap.
    Requiert nmap installé sur le serveur.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments=args)
        open_ports = {}
        if target in nm.all_hosts():
            tcp_data = nm[target].get('tcp', {})
            for port, info in tcp_data.items():
                open_ports[port] = {
                    "state":   info.get("state", "unknown"),
                    "name":    info.get("name", ""),
                    "product": info.get("product", ""),
                }
        return {
            "host":        target,
            "open_ports":  open_ports,
            "total_scanned": len(open_ports),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur scan : {str(e)}")

# ─── Santé ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "CyberSentinel Pro v1.0"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("core_engine:app", host="0.0.0.0", port=port, reload=False)

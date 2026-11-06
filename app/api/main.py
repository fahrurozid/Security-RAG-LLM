from fastapi import FastAPI

app = FastAPI(
    title="Cyber RAG API",
    description="SOC Incident Analysis and Reporting API",
    version="1.0.0",
)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "cyber-rag-api",
    }

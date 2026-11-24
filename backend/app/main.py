from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base
from app.routers import scanner, history, vulnerabilities, assistant, reports

# Ensure database tables are created
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SecureExplain AI - Cybersecurity Analysis API",
    description="Automated defensive website security assessment and Generative AI vulnerability explanation engine.",
    version="1.0.0"
)

# CORS configuration
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    settings.FRONTEND_URL,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow development and production frontend origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(scanner.router)
app.include_router(history.router)
app.include_router(vulnerabilities.router)
app.include_router(assistant.router)
app.include_router(reports.router)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SecureExplain AI API",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.BACKEND_HOST, port=settings.BACKEND_PORT, reload=True)

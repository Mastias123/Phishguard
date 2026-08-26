"""FastAPI application for PhishGuard analysis server."""

from typing import List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from phishguard.mail.parser import MimeParser
from phishguard.scoring.scorer import RiskScorer


class AnalyzeRequest(BaseModel):
    """Request model for email analysis."""
    mime_content: str
    provider: str = "unknown"


class AnalysisReason(BaseModel):
    """Individual reason in analysis result."""
    category: str
    severity: str
    reason: str
    confidence: float


class AnalyzeResponse(BaseModel):
    """Response model for analysis result."""
    score: int
    risk_level: str
    summary: str
    reasons: List[AnalysisReason]


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="PhishGuard API",
        description="Provider-independent phishing detection system",
        version="0.1.0",
    )
    
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {
            "name": "PhishGuard",
            "version": "0.1.0",
            "description": "Phishing detection API",
            "docs": "/docs",
        }
    
    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy"}
    
    @app.post("/analyze", response_model=AnalyzeResponse)
    async def analyze(request: AnalyzeRequest):
        """Analyze an email for phishing indicators.
        
        Accepts raw MIME content and returns risk score with reasons.
        """
        try:
            # Parse email
            email = MimeParser.parse(request.mime_content, provider=request.provider)
            
            # Score email (no analyzers yet - Phase 3)
            scorer = RiskScorer([])
            result = scorer.score(email)
            
            # Convert reasons to response model
            reasons = [
                AnalysisReason(
                    category=reason.category,
                    severity=reason.severity,
                    reason=reason.reason,
                    confidence=reason.confidence,
                )
                for reason in result.reasons
            ]
            
            return AnalyzeResponse(
                score=result.score,
                risk_level=result.get_risk_level(),
                summary=result.summary,
                reasons=reasons,
            )
            
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Analysis failed: {str(e)}",
            )
    
    @app.post("/analyze/test")
    async def analyze_test():
        """Quick test endpoint with sample phishing email."""
        sample_mime = """From: "MitID Kundeservice" <contat@residenceleprogres.com>
To: user@example.com
Subject: Vigtig sikkerhedsopdatering
Date: Mon, 25 Aug 2026 10:00:00 +0000
Authentication-Results: spf=none; dkim=permerror; dmarc=none

Din konto kræver sikkerhedsopdatering.
Opdater nu: https://sender10.zohoinsights.com/update

Hvis du ikke handler inden 24 timer, låses din konto."""
        
        email = MimeParser.parse(sample_mime)
        scorer = RiskScorer([])
        result = scorer.score(email)
        
        reasons = [
            AnalysisReason(
                category=reason.category,
                severity=reason.severity,
                reason=reason.reason,
                confidence=reason.confidence,
            )
            for reason in result.reasons
        ]
        
        return AnalyzeResponse(
            score=result.score,
            risk_level=result.get_risk_level(),
            summary=result.summary,
            reasons=reasons,
        )
    
    return app

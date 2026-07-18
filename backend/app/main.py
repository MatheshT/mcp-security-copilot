from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import router as api_router

app = FastAPI(
    title='Security Copilot API',
    version='1.0.0',
    description='Backend for AI-powered security investigation and SOC reporting.',
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

app.include_router(api_router)


@app.get('/health', summary='Health check endpoint')
def health():
    return {'status': 'ok'}

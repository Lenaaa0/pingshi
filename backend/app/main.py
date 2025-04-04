from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import security  # 移除 logs 导入

app = FastAPI(title="Security Scanner API")

# CORS 设置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # 前端开发服务器地址
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(security.router, prefix="/api/security", tags=["security"])
# app.include_router(logs.router, prefix="/api/logs", tags=["logs"])  # 注释掉这行

@app.get("/")
async def root():
    return {"message": "Security Scanner API"} 
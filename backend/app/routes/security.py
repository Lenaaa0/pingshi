from fastapi import APIRouter, HTTPException, Form, Body
from typing import List, Optional
from app.models.security_log import SecurityLog
from app.models.scan_result import ScanResult
from app.services.scanner import SecurityScanner
from pydantic import BaseModel

router = APIRouter()
scanner = SecurityScanner()

# 定义请求模型
class ScanRequest(BaseModel):
    target: str
    scan_type: str

@router.get("/logs", response_model=List[SecurityLog])
async def get_security_logs():
    return await scanner.get_logs()

@router.get("/status")
async def get_security_status():
    return await scanner.get_status()

@router.post("/scan")
async def start_scan(scan_request: ScanRequest):
    try:
        print(f"收到扫描请求: 目标={scan_request.target}, 类型={scan_request.scan_type}")
        scan_id = await scanner.start_scan(scan_request.target, scan_request.scan_type)
        return {"scan_id": scan_id, "status": "started"}
    except Exception as e:
        print(f"扫描错误: {str(e)}")
        # 返回400错误但提供更友好的消息
        raise HTTPException(status_code=400, detail=f"扫描启动失败: {str(e)}")

@router.get("/results", response_model=List[ScanResult])
async def get_all_scan_results():
    """获取所有扫描结果"""
    return await scanner.get_all_scan_results()

@router.get("/results/latest", response_model=Optional[ScanResult])
async def get_latest_scan_result():
    """获取最新的扫描结果"""
    result = await scanner.get_latest_scan_result()
    if not result:
        raise HTTPException(status_code=404, detail="没有找到扫描结果")
    return result

@router.get("/results/{result_id}", response_model=ScanResult)
async def get_scan_result(result_id: str):
    """获取特定扫描的结果"""
    result = await scanner.get_scan_result(result_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"未找到ID为{result_id}的扫描结果")
    return result 
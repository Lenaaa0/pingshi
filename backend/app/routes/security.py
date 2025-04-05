from fastapi import APIRouter, HTTPException, Form, Body
from typing import List, Optional
from app.models.security_log import SecurityLog
from app.models.scan_result import ScanResult
from app.services.scanner import SecurityScanner
from pydantic import BaseModel
import uuid
import asyncio

router = APIRouter()
scanner = SecurityScanner()

# 存储扫描结果的字典
scan_results = {}

# 定义请求模型
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "port"  # 默认为端口扫描

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
        
        # 生成唯一ID
        scan_id = str(uuid.uuid4())
        print(f"创建扫描结果: ID={scan_id}")
        
        # 存储初始扫描状态
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "status": "started",
            "target": scan_request.target,
            "scan_type": scan_request.scan_type,
            "start_time": None,
            "end_time": None,
            "results": []
        }
        
        # 启动扫描任务
        asyncio.create_task(scanner.run_scan(scan_request.target, scan_request.scan_type, scan_id, scan_results))
        
        return {"scan_id": scan_id, "status": "started"}
    except Exception as e:
        print(f"扫描错误: {str(e)}")
        raise HTTPException(status_code=400, detail=f"扫描启动失败: {str(e)}")

# 获取特定扫描的状态
@router.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    print(f"获取扫描状态: ID={scan_id}")
    
    if scan_id not in scan_results:
        print(f"扫描ID不存在: {scan_id}")
        raise HTTPException(status_code=404, detail=f"未找到ID为{scan_id}的扫描")
    
    return scan_results[scan_id]

# 获取特定扫描的结果
@router.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    print(f"获取扫描结果: ID={scan_id}")
    
    if scan_id not in scan_results:
        print(f"扫描ID不存在: {scan_id}")
        raise HTTPException(status_code=404, detail=f"未找到ID为{scan_id}的扫描结果")
    
    return scan_results[scan_id]

# 保留原有的路由，以保持兼容性
@router.get("/results", response_model=List[dict])
async def get_all_scan_results():
    """获取所有扫描结果"""
    return list(scan_results.values())

@router.get("/results/latest")
async def get_latest_scan_result():
    """获取最新的扫描结果"""
    if not scan_results:
        raise HTTPException(status_code=404, detail="没有找到扫描结果")
    
    # 获取最新的扫描结果（假设是最后添加的）
    latest_id = list(scan_results.keys())[-1]
    return scan_results[latest_id]

@router.get("/results/{result_id}")
async def get_scan_result(result_id: str):
    """获取特定扫描的结果"""
    if result_id not in scan_results:
        raise HTTPException(status_code=404, detail=f"未找到ID为{result_id}的扫描结果")
    
    return scan_results[result_id]

@router.post("/scan/schedule")
async def schedule_scan(
    target: str = Form(...),
    scan_type: str = Form(...),
    schedule_type: str = Form(...),
    schedule_time: str = Form(...),
    schedule_day: Optional[int] = Form(None),
    schedule_weekday: Optional[int] = Form(None)
):
    """排程扫描"""
    try:
        schedule = {
            "type": schedule_type,
            "time": schedule_time
        }
        
        if schedule_type == "weekly" and schedule_weekday is not None:
            schedule["weekday"] = schedule_weekday
        elif schedule_type == "monthly" and schedule_day is not None:
            schedule["day"] = schedule_day
            
        scan_id = await scanner.schedule_scan(target, scan_type, schedule)
        return {"scan_id": scan_id, "status": "scheduled"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"排程扫描失败: {str(e)}")

@router.get("/schedules")
async def get_scan_schedules():
    """获取所有排程扫描"""
    return scanner.scheduled_scans

@router.delete("/schedule/{schedule_id}")
async def delete_scan_schedule(schedule_id: str):
    """删除排程扫描"""
    if schedule_id in scanner.scheduled_scans:
        del scanner.scheduled_scans[schedule_id]
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail=f"未找到ID为{schedule_id}的排程")

@router.get("/vulnerabilities/search")
async def search_vulnerabilities(keyword: str):
    """搜索漏洞数据库"""
    results = scanner.vuln_db.search_vulnerability(keyword)
    return results

@router.post("/vulnerabilities/update")
async def update_vulnerability_database():
    """更新漏洞数据库"""
    success, message = await scanner.vuln_db.update_database()
    if success:
        return {"status": "success", "message": message}
    raise HTTPException(status_code=400, detail=message) 
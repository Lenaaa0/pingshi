from datetime import datetime
import requests
import json
import os

class VulnerabilityDatabase:
    def __init__(self, db_path="./data/vuln_db.json"):
        self.db_path = db_path
        self.vulnerabilities = self._load_database()
        self.last_update = self._get_last_update_time()
        
    def _load_database(self):
        """加载漏洞数据库"""
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r') as f:
                    return json.load(f)
            else:
                # 确保目录存在
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
                # 创建一个空的数据库
                empty_db = {
                    "last_update": datetime.now().isoformat(),
                    "vulnerabilities": []
                }
                with open(self.db_path, 'w') as f:
                    json.dump(empty_db, f, indent=2)
                return empty_db
        except Exception as e:
            print(f"加载漏洞数据库失败: {str(e)}")
            return {"last_update": "", "vulnerabilities": []}
    
    def _get_last_update_time(self):
        """获取上次更新时间"""
        if "last_update" in self.vulnerabilities:
            return self.vulnerabilities["last_update"]
        return ""
    
    async def update_database(self):
        """从网络更新漏洞数据库"""
        try:
            # 从CVE数据源获取最新漏洞信息
            # 这里使用NVD API作为示例
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"pubStartDate": self.last_update, "resultsPerPage": 2000}
            )
            
            if response.status_code == 200:
                data = response.json()
                # 解析和处理新的漏洞数据
                new_vulns = self._process_nvd_data(data)
                
                # 更新本地数据库
                if "vulnerabilities" not in self.vulnerabilities:
                    self.vulnerabilities["vulnerabilities"] = []
                    
                self.vulnerabilities["vulnerabilities"].extend(new_vulns)
                self.vulnerabilities["last_update"] = datetime.now().isoformat()
                
                # 保存到文件
                with open(self.db_path, 'w') as f:
                    json.dump(self.vulnerabilities, f, indent=2)
                    
                return True, f"更新了{len(new_vulns)}个新漏洞"
            else:
                return False, f"API请求失败: {response.status_code}"
                
        except Exception as e:
            return False, f"更新漏洞数据库失败: {str(e)}"
    
    def _process_nvd_data(self, data):
        """处理NVD API返回的数据"""
        new_vulns = []
        try:
            if "vulnerabilities" in data:
                for item in data["vulnerabilities"]:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    
                    if not cve_id:
                        continue
                        
                    # 获取严重程度
                    metrics = cve.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", [{}])[0] if "cvssMetricV31" in metrics else \
                               metrics.get("cvssMetricV30", [{}])[0] if "cvssMetricV30" in metrics else \
                               metrics.get("cvssMetricV2", [{}])[0] if "cvssMetricV2" in metrics else {}
                               
                    base_score = 0
                    severity = "low"
                    
                    if "cvssData" in cvss_data:
                        base_score = cvss_data["cvssData"].get("baseScore", 0)
                        
                        if base_score >= 7.0:
                            severity = "high"
                        elif base_score >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                    
                    # 获取描述
                    descriptions = cve.get("descriptions", [])
                    description = ""
                    
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
                    
                    # 构建漏洞记录
                    vuln = {
                        "id": cve_id,
                        "name": cve_id,
                        "severity": severity,
                        "description": description,
                        "base_score": base_score,
                        "published": cve.get("published"),
                        "recommendation": "查看完整CVE详情以获取修复建议"
                    }
                    
                    new_vulns.append(vuln)
        except Exception as e:
            print(f"处理NVD数据失败: {str(e)}")
            
        return new_vulns
        
    def search_vulnerability(self, keyword):
        """搜索漏洞信息"""
        results = []
        keyword = keyword.lower()
        
        if "vulnerabilities" in self.vulnerabilities:
            for vuln in self.vulnerabilities["vulnerabilities"]:
                if (keyword in vuln.get("id", "").lower() or 
                    keyword in vuln.get("name", "").lower() or 
                    keyword in vuln.get("description", "").lower()):
                    results.append(vuln)
                    
        return results 
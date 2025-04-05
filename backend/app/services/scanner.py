from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import uuid
import threading
import socket
import ssl
import re
import http.client
from app.models.security_log import SecurityLog
from app.models.scan_result import ScanResult, VulnerabilityDetail, PortDetail
import traceback
import asyncio
import requests
import calendar  # 独立导入calendar模块
import os
import dns.resolver

class SecurityScanner:
    def __init__(self):
        # 存储扫描结果的内存字典
        self._scan_results = {}
        self.scheduled_scans = {}
        self._scheduler_running = False
        
    async def get_logs(self) -> List[SecurityLog]:
        # 模拟一些日志数据
        return [
            SecurityLog(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                event_type="端口扫描",
                severity="high",
                description="检测到来自 IP 192.168.1.100 的端口扫描"
            ),
            SecurityLog(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                event_type="登录尝试",
                severity="medium",
                description="多次失败的登录尝试"
            ),
            SecurityLog(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                event_type="系统更新",
                severity="low",
                description="系统安全补丁已更新"
            )
        ]

    async def get_status(self):
        return {"status": "operational"}

    async def start_scan(self, target: str, scan_type: str) -> str:
        # 基本验证
        if not target:
            raise ValueError("目标地址不能为空")
        
        # 记录扫描请求
        print(f"开始扫描: 目标={target}, 类型={scan_type}")
        
        # 生成扫描ID
        scan_id = str(uuid.uuid4())
        
        # 创建初始扫描结果
        result_id = str(uuid.uuid4())
        scan_result = ScanResult(
            id=result_id,
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
            start_time=datetime.now(),
            status="running",
            summary=f"正在扫描 {target}"
        )
        
        # 存储扫描结果
        self._scan_results[result_id] = scan_result
        print(f"创建扫描结果: ID={result_id}")
        
        # 启动实际扫描
        self._start_real_scan(result_id, target, scan_type)
        
        return scan_id
    
    def _start_real_scan(self, result_id: str, target: str, scan_type: str):
        """启动实际的扫描过程"""
        def run_scan():
            try:
                result = self._scan_results.get(result_id)
                if not result:
                    return
                
                if scan_type == 'port':
                    # 执行端口扫描
                    self._perform_port_scan(result_id, target)
                else:
                    # 执行漏洞扫描
                    self._perform_vulnerability_scan(result_id, target)
            except Exception as e:
                print(f"扫描错误: {str(e)}")
                # 更新为失败状态
                if result_id in self._scan_results:
                    result = self._scan_results[result_id]
                    updated_result = ScanResult(
                        id=result.id,
                        scan_id=result.scan_id,
                        target=result.target,
                        scan_type=result.scan_type,
                        start_time=result.start_time,
                        end_time=datetime.now(),
                        status="failed",
                        summary=f"扫描失败: {str(e)}"
                    )
                    self._scan_results[result_id] = updated_result
        
        # 启动扫描线程
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
    
    def _perform_port_scan(self, result_id: str, target: str):
        """执行纯Python的端口扫描"""
        result = self._scan_results.get(result_id)
        if not result:
            return
        
        try:
            print(f"开始端口扫描: {target}")
            # 解析目标地址
            try:
                ip = socket.gethostbyname(target)
                print(f"目标IP: {ip}")
            except socket.gaierror:
                raise ValueError(f"无法解析目标地址: {target}")
            
            # 扩展端口列表，包括常见服务端口和一些高端口
            common_ports = [
                21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 
                443, 445, 993, 995, 1023, 1025, 1049, 1433, 1723, 
                3306, 3389, 5900, 8080, 8443
            ]
            
            open_ports = []
            vulnerabilities = []
            
            # 扫描端口
            for port in common_ports:
                try:
                    print(f"扫描端口: {port}")
                    # 创建套接字
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)  # 设置超时时间
                    
                    # 尝试连接
                    result_code = s.connect_ex((ip, port))
                    
                    # 如果端口开放
                    if result_code == 0:
                        print(f"端口 {port} 开放")
                        
                        # 根据端口识别常见服务
                        service_name = self._get_default_service_name(port)
                        service_version = "unknown"
                        
                        # 尝试获取更多服务信息
                        try:
                            if port in [80, 8080]:
                                # HTTP服务
                                conn = http.client.HTTPConnection(ip, port, timeout=2)
                                conn.request("HEAD", "/")
                                response = conn.getresponse()
                                headers = {h[0].lower(): h[1] for h in response.getheaders()}
                                if 'server' in headers:
                                    service_version = headers['server']
                                conn.close()
                            elif port in [443, 8443]:
                                # HTTPS服务
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                conn = http.client.HTTPSConnection(ip, port, context=context, timeout=2)
                                conn.request("HEAD", "/")
                                response = conn.getresponse()
                                headers = {h[0].lower(): h[1] for h in response.getheaders()}
                                if 'server' in headers:
                                    service_version = headers['server']
                                conn.close()
                            elif port == 22:
                                # SSH服务
                                ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                ssh_socket.settimeout(2)
                                ssh_socket.connect((ip, port))
                                banner = ssh_socket.recv(1024).decode('utf-8', errors='ignore')
                                ssh_socket.close()
                                if banner:
                                    service_version = banner.strip()
                            elif port == 21:
                                # FTP服务
                                ftp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                ftp_socket.settimeout(2)
                                ftp_socket.connect((ip, port))
                                banner = ftp_socket.recv(1024).decode('utf-8', errors='ignore')
                                ftp_socket.close()
                                if banner:
                                    service_version = banner.strip()
                        except Exception as e:
                            print(f"服务识别错误: {str(e)}")
                        
                        port_detail = PortDetail(
                            port=port,
                            service=service_name,
                            state="open",
                            version=service_version
                        )
                        open_ports.append(port_detail)
                    
                    s.close()
                except Exception as e:
                    print(f"扫描端口 {port} 时出错: {str(e)}")
            
            # 计算风险评分
            risk_score = self._calculate_risk_score(open_ports, vulnerabilities)
            
            # 生成摘要
            summary = f"扫描完成。在 {target} 上发现 {len(open_ports)} 个开放端口"
            if vulnerabilities:
                summary += f"和 {len(vulnerabilities)} 个潜在漏洞"
            summary += "。"
            
            print(f"扫描结果: {summary}")
            
            # 更新扫描结果
            updated_result = ScanResult(
                id=result.id,
                scan_id=result.scan_id,
                target=result.target,
                scan_type=result.scan_type,
                start_time=result.start_time,
                end_time=datetime.now(),
                status="completed",
                summary=summary,
                vulnerabilities=vulnerabilities,
                open_ports=open_ports,
                risk_score=risk_score
            )
            
            self._scan_results[result_id] = updated_result
            
        except Exception as e:
            print(f"端口扫描错误: {str(e)}")
            # 更新为失败状态
            updated_result = ScanResult(
                id=result.id,
                scan_id=result.scan_id,
                target=result.target,
                scan_type=result.scan_type,
                start_time=result.start_time,
                end_time=datetime.now(),
                status="failed",
                summary=f"端口扫描失败: {str(e)}"
            )
            self._scan_results[result_id] = updated_result
    
    def _get_default_service_name(self, port):
        """根据端口号获取默认服务名称"""
        service_map = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            115: "sftp",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1049: "td-postman",
            1433: "ms-sql-s",
            1723: "pptp",
            3306: "mysql",
            3389: "rdp",
            5900: "vnc",
            8080: "http-proxy",
            8443: "https-alt"
        }
        return service_map.get(port, "unknown")
    
    async def _perform_vulnerability_scan(self, result_id: str, target: str):
        """增强版的漏洞扫描方法"""
        print(f"开始漏洞扫描: {target}")
        
        try:
            # 解析目标IP
            ip = socket.gethostbyname(target)
            print(f"目标IP: {ip}")
        except socket.gaierror:
            return [{"name": "DNS解析失败", "severity": "high", "description": f"无法解析主机名: {target}", "recommendation": "检查目标域名是否正确"}]
        
        # 存储发现的漏洞
        vulnerabilities = []
        
        # 1. 端口扫描部分
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
                await asyncio.sleep(0.05)  # 短暂暂停，避免过快扫描
            except:
                pass
        
        # 2. 根据开放端口添加相应的漏洞检测
        # 这部分代码与你现有的实现类似，但我们可以添加更多检测
        
        # 3. 添加新的漏洞检测方法
        # Web应用安全检测
        if 80 in open_ports or 443 in open_ports or 8080 in open_ports or 8443 in open_ports:
            protocol = "https" if (443 in open_ports or 8443 in open_ports) else "http"
            port = 443 if 443 in open_ports else 8443 if 8443 in open_ports else 80 if 80 in open_ports else 8080
            base_url = f"{protocol}://{target}" if port in [80, 443] else f"{protocol}://{target}:{port}"
            
            try:
                # 检查Web服务器信息
                response = requests.get(base_url, timeout=3, verify=False, allow_redirects=True)
                server = response.headers.get('Server', '')
                
                if server:
                    vulnerabilities.append({
                        "name": "Web服务器信息泄露",
                        "severity": "low",
                        "description": f"Web服务器暴露了版本信息: {server}",
                        "recommendation": "配置Web服务器，隐藏版本信息"
                    })
                    
                    # 检查常见有漏洞的Web服务器版本
                    if 'Apache/2.4.49' in server or 'Apache/2.4.50' in server:
                        vulnerabilities.append({
                            "name": "Apache路径穿越漏洞(CVE-2021-41773/CVE-2021-42013)",
                            "severity": "high",
                            "description": "检测到易受路径穿越攻击的Apache版本",
                            "recommendation": "立即升级Apache到最新版本"
                        })
                    elif server.startswith('nginx/') and server < 'nginx/1.20.0':
                        vulnerabilities.append({
                            "name": "过时的Nginx版本",
                            "severity": "medium",
                            "description": f"检测到可能存在漏洞的Nginx版本: {server}",
                            "recommendation": "升级Nginx到最新稳定版本"
                        })
                    
                # 检查Web应用安全
                self._check_web_security(base_url, vulnerabilities)
                
                # 检查常见的Web漏洞
                self._check_sql_injection(base_url, vulnerabilities)
                self._check_xss_vulnerability(base_url, vulnerabilities)
                self._check_directory_traversal(base_url, vulnerabilities)
                self._check_sensitive_files(base_url, vulnerabilities)
                
                # 检查Web应用框架
                self._check_web_frameworks(base_url, vulnerabilities)
                
            except Exception as e:
                print(f"Web检测错误: {str(e)}")
        
        # SMTP服务检测
        if 25 in open_ports:
            self._check_smtp_vulnerabilities(target, vulnerabilities)
        
        # DNS服务检测
        if 53 in open_ports:
            self._check_dns_zone_transfer(target, vulnerabilities)
        
        # 数据库服务检测
        if 3306 in open_ports:  # MySQL
            self._check_mysql_vulnerabilities(target, vulnerabilities)
        if 1433 in open_ports:  # MSSQL
            self._check_mssql_vulnerabilities(target, vulnerabilities)
        if 5432 in open_ports:  # PostgreSQL
            self._check_postgresql_vulnerabilities(target, vulnerabilities)
        if 27017 in open_ports:  # MongoDB
            self._check_mongodb_vulnerabilities(target, vulnerabilities)
        
        # Redis检测
        if 6379 in open_ports:
            self._check_redis_vulnerabilities(target, vulnerabilities)
        
        # SMB/NetBIOS检测
        if 445 in open_ports or 139 in open_ports:
            self._check_smb_vulnerabilities(target, vulnerabilities)
        
        # 如果没有发现漏洞，返回一个友好的消息
        if not vulnerabilities:
            vulnerabilities.append({
                "name": "未发现明显漏洞",
                "severity": "info",
                "description": "在基本扫描中未发现明显的安全漏洞。",
                "recommendation": "继续保持良好的安全实践，定期进行更深入的安全评估。"
            })
        
        return vulnerabilities
    
    def _check_web_security(self, target, vulnerabilities):
        """更全面的Web安全检测"""
        base_url = f"http://{target}" if not target.startswith("http") else target
        
        # 检查HTTP安全头部
        try:
            response = requests.get(base_url, timeout=3, verify=False)
            headers = response.headers
            
            # 检查是否缺少重要的安全头
            if 'X-Frame-Options' not in headers:
                vulnerabilities.append({
                    "name": "缺少X-Frame-Options头",
                    "severity": "medium",
                    "description": "网站缺少X-Frame-Options头部，可能容易受到点击劫持攻击",
                    "recommendation": "添加X-Frame-Options头，设置为DENY或SAMEORIGIN"
                })
                
            if 'Content-Security-Policy' not in headers:
                vulnerabilities.append({
                    "name": "缺少内容安全策略(CSP)",
                    "severity": "medium",
                    "description": "网站未实施内容安全策略，这有助于防御多种攻击，包括XSS和数据注入攻击",
                    "recommendation": "实施内容安全策略(CSP)，限制资源加载来源"
                })
                
            if 'Strict-Transport-Security' not in headers and base_url.startswith('https'):
                vulnerabilities.append({
                    "name": "缺少HSTS头",
                    "severity": "medium",
                    "description": "HTTPS站点未使用HTTP严格传输安全(HSTS)头，可能导致降级攻击",
                    "recommendation": "添加Strict-Transport-Security头，并设置适当的max-age"
                })
                
            # 检查Cookie安全性
            if 'Set-Cookie' in headers:
                cookies = headers['Set-Cookie']
                if 'HttpOnly' not in cookies:
                    vulnerabilities.append({
                        "name": "Cookie缺少HttpOnly标志",
                        "severity": "medium",
                        "description": "Cookie未设置HttpOnly标志，可能被JavaScript访问，增加XSS攻击风险",
                        "recommendation": "对敏感Cookie设置HttpOnly标志"
                    })
                    
                if 'Secure' not in cookies and base_url.startswith('https'):
                    vulnerabilities.append({
                        "name": "Cookie缺少Secure标志",
                        "severity": "medium",
                        "description": "HTTPS站点的Cookie未设置Secure标志，可能通过HTTP传输",
                        "recommendation": "对HTTPS站点的Cookie设置Secure标志"
                    })
                    
                if 'SameSite' not in cookies:
                    vulnerabilities.append({
                        "name": "Cookie缺少SameSite属性",
                        "severity": "low",
                        "description": "Cookie未设置SameSite属性，可能容易受到CSRF攻击",
                        "recommendation": "设置SameSite=Lax或SameSite=Strict属性"
                    })
        except Exception as e:
            print(f"检查Web安全时出错: {str(e)}")
    
    def _check_sql_injection(self, base_url, vulnerabilities):
        """检查SQL注入漏洞"""
        try:
            # 常见的SQL注入测试路径和参数
            test_paths = [
                "/search.php?q=test'",
                "/product.php?id=1'",
                "/article.php?id=1'",
                "/item.php?id=1'",
                "/view.php?page=1'",
                "/index.php?id=1'",
                "/profile.php?user=1'",
                "/artists.php?artist=1'",
                # 添加ASP和ASP.NET常见路径
                "/search.aspx?q=test'",
                "/product.aspx?id=1'",
                "/article.aspx?id=1'",
                "/item.aspx?id=1'",
                "/view.aspx?page=1'",
                "/index.aspx?id=1'",
                "/profile.aspx?user=1'",
                "/login.aspx?username=test'",
                "/bank/login.aspx?uid=test'",
                "/bank/account.aspx?id=1'"
            ]
            
            # SQL错误关键词 - 添加更多ASP.NET相关错误
            sql_errors = [
                "sql syntax", "syntax error", "mysql_fetch", "mysql_num_rows",
                "mysql_query", "pg_query", "sqlite_query", "oracle error",
                "warning: mysql", "unclosed quotation", "you have an error in your sql",
                "odbc_", "sqlstate", "microsoft sql", "postgresql error", "sqlite error",
                # ASP.NET SQL错误
                "system.data.sqlclient", "oledb", "sql server error", "incorrect syntax",
                "unclosed quotation mark after", "conversion failed when converting",
                "string or binary data would be truncated"
            ]
            
            # 添加基于行为的SQL注入检测
            # 测试 AND 1=1 (应该返回正常结果)
            # 测试 AND 1=2 (应该返回不同结果)
            behavior_tests = [
                {"path": "/bank/login.aspx?uid=1", "suffix1": " AND 1=1", "suffix2": " AND 1=2"},
                {"path": "/bank/account.aspx?id=1", "suffix1": " AND 1=1", "suffix2": " AND 1=2"}
            ]
            
            # 先进行基于错误的检测
            for path in test_paths:
                try:
                    url = base_url + path
                    print(f"测试SQL注入: {url}")
                    
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    }
                    response = requests.get(url, headers=headers, timeout=5, verify=False)
                    
                    # 检查响应中是否包含SQL错误
                    content = response.text.lower()
                    for error in sql_errors:
                        if error in content:
                            vulnerabilities.append(
                                VulnerabilityDetail(
                                    name="SQL注入漏洞",
                                    severity="high",
                                    description=f"在{url}发现潜在的SQL注入漏洞。响应中包含SQL错误信息。",
                                    recommendation="使用参数化查询或预处理语句，避免直接拼接SQL语句。"
                                )
                            )
                            print(f"发现漏洞: SQL注入 ({url})")
                            break
                except Exception as e:
                    print(f"测试SQL注入时出错: {str(e)}")
            
            # 然后进行基于行为的检测
            for test in behavior_tests:
                try:
                    url1 = base_url + test["path"] + test["suffix1"]
                    url2 = base_url + test["path"] + test["suffix2"]
                    
                    print(f"测试基于行为的SQL注入: {url1} vs {url2}")
                    
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    }
                    
                    response1 = requests.get(url1, headers=headers, timeout=5, verify=False)
                    response2 = requests.get(url2, headers=headers, timeout=5, verify=False)
                    
                    # 如果两个响应明显不同，可能存在SQL注入
                    if (len(response1.text) - len(response2.text) > 100 or 
                        response1.status_code != response2.status_code):
                        vulnerabilities.append(
                            VulnerabilityDetail(
                                name="SQL注入漏洞",
                                severity="high",
                                description=f"在{test['path']}发现潜在的SQL注入漏洞。通过比较 AND 1=1 与 AND 1=2 的响应差异检测到。",
                                recommendation="使用参数化查询或预处理语句，避免直接拼接SQL语句。"
                            )
                        )
                        print(f"发现漏洞: 基于行为的SQL注入 ({test['path']})")
                except Exception as e:
                    print(f"测试基于行为的SQL注入时出错: {str(e)}")
                
        except Exception as e:
            print(f"SQL注入检查错误: {str(e)}")
    
    def _check_xss_vulnerability(self, base_url, vulnerabilities):
        """检查XSS漏洞"""
        try:
            # XSS测试向量
            xss_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>"
            ]
            
            # 常见的XSS测试路径
            test_paths = [
                "/search.php?q=PAYLOAD",
                "/comment.php?text=PAYLOAD",
                "/profile.php?name=PAYLOAD",
                "/feedback.php?message=PAYLOAD",
                "/guestbook.php?entry=PAYLOAD"
            ]
            
            for path in test_paths:
                for payload in xss_payloads:
                    try:
                        url = base_url + path.replace("PAYLOAD", payload)
                        print(f"测试XSS: {url}")
                        
                        # 使用requests库进行HTTP请求
                        response = requests.get(url, timeout=5, verify=False)
                        
                        # 检查响应中是否包含未经转义的XSS payload
                        if payload in response.text:
                            vulnerabilities.append(
                                VulnerabilityDetail(
                                    name="跨站脚本(XSS)漏洞",
                                    severity="high",
                                    description=f"在{url}发现潜在的XSS漏洞。网站未正确过滤或转义用户输入。",
                                    recommendation="对所有用户输入进行适当的验证和转义，使用内容安全策略(CSP)。"
                                )
                            )
                            print(f"发现漏洞: XSS ({url})")
                            # 找到一个漏洞后就跳出当前路径的测试
                            break
                    except Exception as e:
                        print(f"测试XSS时出错: {str(e)}")
        except Exception as e:
            print(f"XSS检查错误: {str(e)}")
    
    def _check_directory_traversal(self, base_url, vulnerabilities):
        """检查目录遍历漏洞"""
        try:
            # 常见的目录遍历测试路径
            test_paths = [
                "/index.php?file=../../../etc/passwd",
                "/page.php?include=../../../etc/passwd",
                "/download.php?path=../../../etc/passwd",
                "/view.php?page=../../../etc/passwd",
                "/content.php?file=../../../etc/passwd"
            ]
            
            # 目录遍历成功的关键词
            traversal_indicators = [
                "root:x:", "bin:x:", "nobody:x:", "www-data", 
                "lp:x:", "sync:x:", "shutdown:x:", "halt:x:",
                "mail:x:", "news:x:", "uucp:x:", "operator:x:"
            ]
            
            for path in test_paths:
                try:
                    url = base_url + path
                    print(f"测试目录遍历: {url}")
                    
                    # 使用requests库进行HTTP请求
                    response = requests.get(url, timeout=5, verify=False)
                    
                    # 检查响应中是否包含目录遍历成功的迹象
                    content = response.text
                    for indicator in traversal_indicators:
                        if indicator in content:
                            vulnerabilities.append(
                                VulnerabilityDetail(
                                    name="目录遍历漏洞",
                                    severity="high",
                                    description=f"在{url}发现潜在的目录遍历漏洞。网站可能允许访问服务器上的敏感文件。",
                                    recommendation="验证所有文件路径，使用白名单而非黑名单，避免直接使用用户输入作为文件路径。"
                                )
                            )
                            print(f"发现漏洞: 目录遍历 ({url})")
                            break
                except Exception as e:
                    print(f"测试目录遍历时出错: {str(e)}")
        except Exception as e:
            print(f"目录遍历检查错误: {str(e)}")
    
    def _check_sensitive_files(self, base_url, vulnerabilities):
        """检查敏感文件泄露"""
        try:
            # 常见的敏感文件路径
            sensitive_files = [
                "/.git/config",
                "/.env",
                "/config.php.bak",
                "/wp-config.php.bak",
                "/robots.txt",
                "/.htaccess",
                "/server-status",
                "/phpinfo.php",
                "/info.php",
                "/admin/",
                "/backup/",
                "/db/",
                "/logs/",
                "/test.php",
                "/temp/",
                "/install/",
                "/setup/",
                "/config/",
                "/.svn/entries",
                "/.git/HEAD"
            ]
            
            for path in sensitive_files:
                try:
                    url = base_url + path
                    print(f"检查敏感文件: {url}")
                    
                    # 使用requests库进行HTTP请求
                    response = requests.get(url, timeout=5, verify=False)
                    
                    # 检查是否能访问敏感文件
                    if response.status_code == 200:
                        # 排除一些常见的正常文件，如robots.txt
                        if path == "/robots.txt" and len(response.text) < 100:
                            continue
                            
                        vulnerabilities.append(
                            VulnerabilityDetail(
                                name="敏感文件泄露",
                                severity="medium",
                                description=f"发现敏感文件: {url}。这可能泄露服务器配置或其他敏感信息。",
                                recommendation="限制对敏感文件的访问，移除不必要的文件，配置适当的访问控制。"
                            )
                        )
                        print(f"发现漏洞: 敏感文件泄露 ({url})")
                except Exception as e:
                    print(f"检查敏感文件时出错: {str(e)}")
        except Exception as e:
            print(f"敏感文件检查错误: {str(e)}")
    
    def _check_file_upload_vulnerability(self, base_url, vulnerabilities):
        """检查文件上传漏洞"""
        upload_urls = ["/userinfo.php"]
        # 实现检测逻辑
    
    def _calculate_risk_score(self, open_ports, vulnerabilities):
        """计算风险评分"""
        score = 0
        
        # 根据开放端口计算分数
        score += len(open_ports) * 5
        
        # 根据漏洞严重性计算分数
        for vuln in vulnerabilities:
            if vuln.severity == 'high':
                score += 30
            elif vuln.severity == 'medium':
                score += 15
            else:
                score += 5
        
        # 确保分数在0-100范围内
        return min(100, score)
    
    async def get_scan_result(self, result_id: str) -> Optional[ScanResult]:
        """获取特定扫描的结果"""
        return self._scan_results.get(result_id)
    
    async def get_all_scan_results(self) -> List[ScanResult]:
        """获取所有扫描结果"""
        return list(self._scan_results.values())
    
    async def get_latest_scan_result(self) -> Optional[ScanResult]:
        """获取最新的扫描结果"""
        print(f"获取最新扫描结果，当前结果数量: {len(self._scan_results)}")
        if not self._scan_results:
            print("没有扫描结果")
            return None
        
        # 按开始时间排序，返回最新的
        sorted_results = sorted(
            self._scan_results.values(), 
            key=lambda x: x.start_time, 
            reverse=True
        )
        result = sorted_results[0] if sorted_results else None
        print(f"最新结果: {result.id if result else 'None'}")
        return result

    async def run_scan(self, target: str, scan_type: str, scan_id: str, scan_results: dict):
        """运行扫描并更新结果"""
        try:
            print(f"开始扫描: 目标={target}, 类型={scan_type}")
            
            # 更新开始时间
            scan_results[scan_id]["start_time"] = datetime.now().isoformat()
            scan_results[scan_id]["status"] = "running"
            
            # 执行扫描
            if scan_type == "port":
                results = await self.scan_ports(target)
            elif scan_type == "vulnerability":
                results = await self.scan_vulnerabilities(target)
            else:
                results = {"error": f"不支持的扫描类型: {scan_type}"}
                scan_results[scan_id]["status"] = "failed"
            
            # 更新扫描结果
            scan_results[scan_id]["results"] = results
            scan_results[scan_id]["end_time"] = datetime.now().isoformat()
            scan_results[scan_id]["status"] = "completed"
            
            print(f"扫描结果: {results}")
            
        except Exception as e:
            print(f"扫描执行错误: {str(e)}")
            scan_results[scan_id]["status"] = "failed"
            scan_results[scan_id]["results"] = {"error": str(e)}
            scan_results[scan_id]["end_time"] = datetime.now().isoformat()

    async def scan_ports(self, target: str) -> List[Dict[str, Any]]:
        """扫描目标的开放端口"""
        print(f"开始端口扫描: {target}")
        
        # 解析目标IP
        try:
            ip = socket.gethostbyname(target)
            print(f"目标IP: {ip}")
        except socket.gaierror:
            return [{"error": f"无法解析主机名: {target}"}]
        
        # 常用端口列表
        common_ports = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 443, 445, 993, 995, 1023, 1025, 1049, 1433, 1723, 3306, 3389, 5900, 8080, 8443]
        
        open_ports = []
        
        # 扫描端口
        for port in common_ports:
            print(f"扫描端口: {port}")
            try:
                # 创建socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 设置超时时间
                
                # 尝试连接
                result = sock.connect_ex((ip, port))
                
                # 如果连接成功，端口开放
                if result == 0:
                    print(f"端口 {port} 开放")
                    open_ports.append({
                        "port": port,
                        "status": "open",
                        "service": self._get_default_service_name(port)
                    })
                
                # 关闭socket
                sock.close()
                
                # 短暂暂停，避免触发目标的防火墙
                await asyncio.sleep(0.1)
                
            except Exception as e:
                print(f"扫描端口 {port} 时出错: {str(e)}")
        
        print(f"扫描结果: 扫描完成。在 {target} 上发现 {len(open_ports)} 个开放端口。")
        
        return open_ports
    
    async def scan_vulnerabilities(self, target: str) -> List[Dict[str, Any]]:
        """增强版的漏洞扫描方法"""
        print(f"开始漏洞扫描: {target}")
        
        try:
            # 解析目标IP
            ip = socket.gethostbyname(target)
            print(f"目标IP: {ip}")
        except socket.gaierror:
            return [{"name": "DNS解析失败", "severity": "high", "description": f"无法解析主机名: {target}", "recommendation": "检查目标域名是否正确"}]
        
        # 存储发现的漏洞
        vulnerabilities = []
        
        # 1. 端口扫描部分
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
                await asyncio.sleep(0.05)  # 短暂暂停，避免过快扫描
            except:
                pass
        
        # 2. 根据开放端口添加相应的漏洞检测
        # 这部分代码与你现有的实现类似，但我们可以添加更多检测
        
        # 3. 添加新的漏洞检测方法
        # Web应用安全检测
        if 80 in open_ports or 443 in open_ports or 8080 in open_ports or 8443 in open_ports:
            protocol = "https" if (443 in open_ports or 8443 in open_ports) else "http"
            port = 443 if 443 in open_ports else 8443 if 8443 in open_ports else 80 if 80 in open_ports else 8080
            base_url = f"{protocol}://{target}" if port in [80, 443] else f"{protocol}://{target}:{port}"
            
            try:
                # 检查Web服务器信息
                response = requests.get(base_url, timeout=3, verify=False, allow_redirects=True)
                server = response.headers.get('Server', '')
                
                if server:
                    vulnerabilities.append({
                        "name": "Web服务器信息泄露",
                        "severity": "low",
                        "description": f"Web服务器暴露了版本信息: {server}",
                        "recommendation": "配置Web服务器，隐藏版本信息"
                    })
                    
                    # 检查常见有漏洞的Web服务器版本
                    if 'Apache/2.4.49' in server or 'Apache/2.4.50' in server:
                        vulnerabilities.append({
                            "name": "Apache路径穿越漏洞(CVE-2021-41773/CVE-2021-42013)",
                            "severity": "high",
                            "description": "检测到易受路径穿越攻击的Apache版本",
                            "recommendation": "立即升级Apache到最新版本"
                        })
                    elif server.startswith('nginx/') and server < 'nginx/1.20.0':
                        vulnerabilities.append({
                            "name": "过时的Nginx版本",
                            "severity": "medium",
                            "description": f"检测到可能存在漏洞的Nginx版本: {server}",
                            "recommendation": "升级Nginx到最新稳定版本"
                        })
                    
                # 检查Web应用安全
                self._check_web_security(base_url, vulnerabilities)
                
                # 检查常见的Web漏洞
                self._check_sql_injection(base_url, vulnerabilities)
                self._check_xss_vulnerability(base_url, vulnerabilities)
                self._check_directory_traversal(base_url, vulnerabilities)
                self._check_sensitive_files(base_url, vulnerabilities)
                
                # 检查Web应用框架
                self._check_web_frameworks(base_url, vulnerabilities)
                
            except Exception as e:
                print(f"Web检测错误: {str(e)}")
        
        # SMTP服务检测
        if 25 in open_ports:
            self._check_smtp_vulnerabilities(target, vulnerabilities)
        
        # DNS服务检测
        if 53 in open_ports:
            self._check_dns_zone_transfer(target, vulnerabilities)
        
        # 数据库服务检测
        if 3306 in open_ports:  # MySQL
            self._check_mysql_vulnerabilities(target, vulnerabilities)
        if 1433 in open_ports:  # MSSQL
            self._check_mssql_vulnerabilities(target, vulnerabilities)
        if 5432 in open_ports:  # PostgreSQL
            self._check_postgresql_vulnerabilities(target, vulnerabilities)
        if 27017 in open_ports:  # MongoDB
            self._check_mongodb_vulnerabilities(target, vulnerabilities)
        
        # Redis检测
        if 6379 in open_ports:
            self._check_redis_vulnerabilities(target, vulnerabilities)
        
        # SMB/NetBIOS检测
        if 445 in open_ports or 139 in open_ports:
            self._check_smb_vulnerabilities(target, vulnerabilities)
        
        # 如果没有发现漏洞，返回一个友好的消息
        if not vulnerabilities:
            vulnerabilities.append({
                "name": "未发现明显漏洞",
                "severity": "info",
                "description": "在基本扫描中未发现明显的安全漏洞。",
                "recommendation": "继续保持良好的安全实践，定期进行更深入的安全评估。"
            })
        
        return vulnerabilities

    def get_service_name(self, port: int) -> str:
        """根据端口号获取服务名称"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            115: "SFTP",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        
        return services.get(port, "未知")

    def _check_additional_vulnerabilities(self, base_url, vulnerabilities):
        """检查其他类型的漏洞"""
        # CSRF 漏洞检测
        self._check_csrf_vulnerability(base_url, vulnerabilities)
        
        # CORS 配置错误检测
        self._check_cors_misconfiguration(base_url, vulnerabilities)
        
        # HTTP 安全头部检测
        self._check_security_headers(base_url, vulnerabilities)
        
        # 弱密码策略检测
        self._check_weak_password_policy(base_url, vulnerabilities)

    def _check_csrf_vulnerability(self, base_url, vulnerabilities):
        """检测CSRF漏洞"""
        try:
            response = requests.get(f"{base_url}")
            if response.status_code == 200:
                # 检查是否存在CSRF token
                has_csrf_token = False
                if 'csrf' in response.text.lower() or 'token' in response.text.lower():
                    has_csrf_token = True
                    
                if not has_csrf_token:
                    vulnerabilities.append({
                        "name": "可能存在CSRF漏洞",
                        "severity": "medium",
                        "description": "网站可能未实施CSRF防护机制，这可能允许攻击者诱导用户执行非预期操作。",
                        "recommendation": "实施CSRF token验证，确保每个敏感操作都要求有效的token。"
                    })
        except Exception as e:
            print(f"CSRF漏洞检测错误: {str(e)}")

    def _check_ssl_security(self, target, vulnerabilities):
        """检查SSL/TLS安全配置"""
        try:
            # 提取主机名
            hostname = target
            if hostname.startswith("http://"):
                hostname = hostname[7:]
            elif hostname.startswith("https://"):
                hostname = hostname[8:]
            
            # 移除路径部分
            if "/" in hostname:
                hostname = hostname.split("/")[0]
            
            # 尝试建立SSL连接
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # 获取SSL证书信息
                    cert = ssock.getpeercert()
                    
                    # 检查证书有效期
                    not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.now()
                    
                    # 证书即将过期检查
                    days_left = (not_after - now).days
                    if days_left < 30:
                        vulnerabilities.append({
                            "name": "SSL证书即将过期",
                            "severity": "medium",
                            "description": f"SSL证书将在{days_left}天后过期",
                            "recommendation": "续签SSL证书，确保服务器使用有效的SSL证书"
                        })
                    
                    # 检查是否支持不安全的协议
                    # 这里需要更详细的实现
        except Exception as e:
            print(f"SSL安全检查错误: {str(e)}")
            vulnerabilities.append({
                "name": "SSL/TLS配置检查失败",
                "severity": "low",
                "description": f"无法检查SSL/TLS配置: {str(e)}",
                "recommendation": "确保服务器配置了正确的SSL/TLS证书和设置"
            })

    def _check_software_dependencies(self, target, vulnerabilities):
        """检查常见软件依赖的已知漏洞"""
        try:
            # 获取HTTP响应头
            response = requests.get(f"https://{target}" if not target.startswith("http") else target)
            headers = response.headers
            
            # 检查服务器软件
            if 'Server' in headers:
                server = headers['Server']
                # 检查常见有漏洞的服务器版本
                if 'Apache/2.4.49' in server or 'Apache/2.4.50' in server:
                    vulnerabilities.append({
                        "name": "Apache路径穿越漏洞(CVE-2021-41773/CVE-2021-42013)",
                        "severity": "high",
                        "description": "检测到易受路径穿越攻击的Apache版本",
                        "recommendation": "升级Apache到最新版本"
                    })
                elif 'nginx/1.18.0' in server:
                    # 添加已知的nginx漏洞检查
                    pass
                
            # 检查常见JavaScript库
            if 'text/html' in response.headers.get('Content-Type', ''):
                html_content = response.text
                # 检查jQuery
                jquery_pattern = r'jquery[.-](\d+\.\d+\.\d+)\.min\.js'
                jquery_match = re.search(jquery_pattern, html_content, re.IGNORECASE)
                if jquery_match:
                    jquery_version = jquery_match.group(1)
                    # 检查有漏洞的jQuery版本
                    if jquery_version < '3.0.0':
                        vulnerabilities.append({
                            "name": f"过时的jQuery版本({jquery_version})",
                            "severity": "medium",
                            "description": "检测到使用过时的jQuery版本，可能存在已知安全漏洞",
                            "recommendation": "升级jQuery到最新版本"
                        })
        except Exception as e:
            print(f"依赖检查错误: {str(e)}")

    def _check_rate_limiting(self, base_url, vulnerabilities):
        """检查API接口是否实施了速率限制"""
        try:
            # 尝试在短时间内多次请求同一个端点
            endpoint = f"{base_url}/api/user" if not base_url.endswith('/') else f"{base_url}api/user"
            
            # 发送多个请求
            max_requests = 20
            responses = []
            for _ in range(max_requests):
                response = requests.get(endpoint, timeout=5)
                responses.append(response.status_code)
            
            # 检查是否所有请求都成功 - 可能没有实施速率限制
            if all(code == 200 for code in responses):
                vulnerabilities.append({
                    "name": "API缺少速率限制",
                    "severity": "medium",
                    "description": "API端点可能没有实施速率限制，这可能会导致滥用和DoS攻击",
                    "recommendation": "实施API速率限制，限制来自单个IP的请求数量"
                })
        except Exception as e:
            print(f"速率限制检查错误: {str(e)}")

    async def schedule_scan(self, target: str, scan_type: str, schedule: dict):
        """
        schedule scan with specified frequency
        schedule: {
            "type": "once"|"daily"|"weekly"|"monthly",
            "time": "HH:MM", 
            "day": 1-31 (for monthly), 
            "weekday": 0-6 (for weekly, 0=Monday)
        }
        """
        scan_id = str(uuid.uuid4())
        
        # Store schedule information
        self.scheduled_scans[scan_id] = {
            "target": target,
            "scan_type": scan_type,
            "schedule": schedule,
            "last_run": None,
            "next_run": self._calculate_next_run(schedule),
            "active": True
        }
        
        # Start the scheduling task if not already running
        if not hasattr(self, '_scheduler_running') or not self._scheduler_running:
            self._scheduler_running = True
            asyncio.create_task(self._run_scheduler())
        
        return scan_id

    def _calculate_next_run(self, schedule):
        """Calculate next run time based on schedule"""
        now = datetime.now()
        schedule_time = datetime.strptime(schedule["time"], "%H:%M").time()
        
        if schedule["type"] == "once":
            return datetime.combine(now.date(), schedule_time)
        
        elif schedule["type"] == "daily":
            next_day = now.date()
            next_run = datetime.combine(next_day, schedule_time)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run
        
        elif schedule["type"] == "weekly":
            weekday = schedule["weekday"]
            days_ahead = weekday - now.weekday()
            if days_ahead <= 0:  # Target day already happened this week
                days_ahead += 7
            next_day = now.date() + timedelta(days=days_ahead)
            return datetime.combine(next_day, schedule_time)
        
        elif schedule["type"] == "monthly":
            day = min(schedule["day"], calendar.monthrange(now.year, now.month)[1])
            next_day = now.replace(day=day).date()
            next_run = datetime.combine(next_day, schedule_time)
            if next_run <= now:
                # Move to next month
                if now.month == 12:
                    next_month = now.replace(year=now.year+1, month=1)
                else:
                    next_month = now.replace(month=now.month+1)
                # Adjust for month length
                day = min(schedule["day"], calendar.monthrange(next_month.year, next_month.month)[1])
                next_day = next_month.replace(day=day).date()
                next_run = datetime.combine(next_day, schedule_time)
            return next_run
        
        return now  # Default to now

    async def _run_scheduler(self):
        """Run the scheduler loop to execute scheduled scans"""
        while True:
            now = datetime.now()
            
            # Check all scheduled scans
            for scan_id, scan_info in self.scheduled_scans.items():
                if not scan_info["active"]:
                    continue
                    
                if scan_info["next_run"] and scan_info["next_run"] <= now:
                    # Time to run this scan
                    target = scan_info["target"]
                    scan_type = scan_info["scan_type"]
                    
                    # Start the scan
                    print(f"执行计划扫描: {target} ({scan_type})")
                    await self.start_scan(target, scan_type)
                    
                    # Update last run time
                    self.scheduled_scans[scan_id]["last_run"] = now
                    
                    # Calculate next run time (except for one-time scans)
                    if scan_info["schedule"]["type"] != "once":
                        self.scheduled_scans[scan_id]["next_run"] = self._calculate_next_run(scan_info["schedule"])
                    else:
                        # Deactivate one-time scan
                        self.scheduled_scans[scan_id]["active"] = False
            
            # Sleep for a minute before checking again
            await asyncio.sleep(60)

    def _check_dns_zone_transfer(self, target, vulnerabilities):
        """检查DNS区域传送漏洞"""
        try:
            # 提取域名
            domain = target
            if domain.startswith("http://"):
                domain = domain[7:]
            elif domain.startswith("https://"):
                domain = domain[8:]
            
            # 移除路径和参数
            if "/" in domain:
                domain = domain.split("/")[0]
            
            # 查询NS记录
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                name_servers = [ns.target.to_text() for ns in ns_records]
                
                for ns in name_servers:
                    try:
                        # 尝试区域传送
                        zone_transfer = os.popen(f"dig @{ns} {domain} AXFR").read()
                        
                        # 检查是否成功
                        if "XFR size" in zone_transfer and "Transfer failed" not in zone_transfer:
                            vulnerabilities.append({
                                "name": "DNS区域传送漏洞",
                                "severity": "high",
                                "description": f"名称服务器 {ns} 允许DNS区域传送，可能泄露所有DNS记录",
                                "recommendation": "在DNS服务器上禁用区域传送或限制为授权服务器"
                            })
                    except Exception as e:
                        print(f"检查DNS区域传送时出错 ({ns}): {str(e)}")
            except Exception as e:
                print(f"解析NS记录时出错: {str(e)}")
        except Exception as e:
            print(f"DNS区域传送检查错误: {str(e)}")

    def _check_smb_vulnerabilities(self, target, vulnerabilities):
        """检查SMB/Windows共享相关漏洞"""
        try:
            # 解析目标IP
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                return
            
            # 检查445端口是否开放
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, 445))
            if result == 0:
                vulnerabilities.append({
                    "name": "SMB服务暴露",
                    "severity": "high",
                    "description": "检测到开放的SMB服务(端口445)，可能存在未授权访问或利用已知漏洞的风险",
                    "recommendation": "如不需要，关闭SMB服务；需要时限制访问IP，并及时更新系统补丁"
                })
            
            # 进一步检查SMB版本
            # 这里需要更复杂的实现，可以考虑使用impacket等库
            
            sock.close()
            
            # 检查139端口(NetBIOS)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, 139))
            if result == 0:
                vulnerabilities.append({
                    "name": "NetBIOS服务暴露",
                    "severity": "medium",
                    "description": "检测到开放的NetBIOS服务(端口139)，可能泄露计算机名和工作组信息",
                    "recommendation": "如不需要，禁用NetBIOS服务"
                })
            sock.close()
        except Exception as e:
            print(f"SMB漏洞检查错误: {str(e)}")

    def _check_web_frameworks(self, base_url, vulnerabilities):
        """检测目标使用的Web框架及其潜在漏洞"""
        try:
            response = requests.get(base_url, timeout=3, verify=False)
            html_content = response.text.lower()
            headers = response.headers
            
            # 检测Laravel
            if 'laravel_session' in response.cookies or '/vendor/laravel/' in html_content:
                vulnerabilities.append({
                    "name": "检测到Laravel框架",
                    "severity": "info",
                    "description": "目标网站可能使用Laravel框架。建议检查是否使用最新版本，以及是否配置了正确的安全设置。",
                    "recommendation": "确保Laravel框架及其依赖项是最新版本，特别注意.env文件是否暴露。"
                })
                
                # 检查Laravel调试模式
                if 'laravel' in html_content and 'stack trace' in html_content and 'error' in html_content:
                    vulnerabilities.append({
                        "name": "Laravel调试模式已启用",
                        "severity": "high",
                        "description": "Laravel框架处于调试模式，可能泄露敏感信息如数据库凭据、应用路径等。",
                        "recommendation": "在生产环境中禁用调试模式，设置APP_DEBUG=false。"
                    })
            
            # 检测WordPress
            if '/wp-content/' in html_content or '/wp-includes/' in html_content or 'wordpress' in html_content:
                vulnerabilities.append({
                    "name": "检测到WordPress",
                    "severity": "info",
                    "description": "目标网站可能是WordPress搭建的。WordPress是常见的攻击目标。",
                    "recommendation": "确保WordPress核心、主题和插件都是最新版本，移除不必要的插件，使用安全插件加强防护。"
                })
                
                # 尝试访问wp-json API
                try:
                    wp_api = requests.get(f"{base_url}/wp-json/", timeout=2, verify=False)
                    if wp_api.status_code == 200 and 'wp/v' in wp_api.text:
                        wp_version = re.search(r'"version":"([\d\.]+)"', wp_api.text)
                        if wp_version:
                            version = wp_version.group(1)
                            vulnerabilities.append({
                                "name": f"WordPress版本暴露 (v{version})",
                                "severity": "medium",
                                "description": f"WordPress REST API暴露了站点使用的WordPress版本 (v{version})，攻击者可以针对特定版本的已知漏洞发起攻击。",
                                "recommendation": "配置Web服务器以限制对wp-json端点的访问，或使用插件隐藏WordPress版本信息。"
                            })
                except:
                    pass
            
            # 检测ThinkPHP
            if 'thinkphp' in html_content or any(h for h in headers.values() if 'thinkphp' in str(h).lower()):
                vulnerabilities.append({
                    "name": "检测到ThinkPHP框架",
                    "severity": "medium",
                    "description": "目标网站可能使用ThinkPHP框架。历史上ThinkPHP存在多个严重远程代码执行漏洞。",
                    "recommendation": "确保使用ThinkPHP的最新安全版本，禁用调试模式，限制错误显示。"
                })
                
            # 检测Django
            if 'csrftoken' in response.cookies or 'django' in html_content:
                vulnerabilities.append({
                    "name": "检测到Django框架",
                    "severity": "info",
                    "description": "目标网站可能使用Django框架。",
                    "recommendation": "确保Django是最新版本，启用所有安全中间件，特别是CSRF保护和XSS过滤。"
                })
            
            # 其他框架检测...
            
        except Exception as e:
            print(f"检查Web框架时出错: {str(e)}")

    def _check_mysql_vulnerabilities(self, target, vulnerabilities):
        """检查MySQL数据库漏洞"""
        try:
            # 这里仅做简单的端口开放检测，实际中可以尝试连接测试
            vulnerabilities.append({
                "name": "MySQL数据库暴露",
                "severity": "high",
                "description": "检测到目标系统开放了MySQL数据库服务(端口3306)，可能存在未授权访问风险。",
                "recommendation": "限制MySQL只允许本地访问；如需远程访问，配置强密码并限制允许的IP地址。"
            })
            
            # 尝试MySQL弱密码测试
            # 这里仅示例，实际中应该谨慎实施，避免过多的登录尝试触发安全机制
            try:
                import pymysql
                common_users = ['root', 'admin', 'mysql']
                common_passwords = ['', 'password', 'root', 'admin', '123456', 'mysql']
                
                for user in common_users:
                    for password in common_passwords:
                        try:
                            conn = pymysql.connect(
                                host=target,
                                user=user,
                                password=password,
                                connect_timeout=1
                            )
                            conn.close()
                            vulnerabilities.append({
                                "name": "MySQL弱密码",
                                "severity": "critical",
                                "description": f"使用常见的用户名和密码组合({user}/{password})成功登录MySQL服务器。",
                                "recommendation": "立即更改MySQL账户密码，使用强密码策略，仅允许必要的数据库用户。"
                            })
                            return  # 找到一个弱密码就停止测试
                        except:
                            pass
            except ImportError:
                print("缺少pymysql模块，跳过MySQL弱密码测试")
            except Exception as e:
                print(f"MySQL弱密码测试错误: {str(e)}")
            
        except Exception as e:
            print(f"MySQL漏洞检查错误: {str(e)}")

    def _check_mongodb_vulnerabilities(self, target, vulnerabilities):
        """检查MongoDB漏洞"""
        try:
            vulnerabilities.append({
                "name": "MongoDB数据库暴露",
                "severity": "high",
                "description": "检测到目标系统开放了MongoDB数据库服务(端口27017)，可能存在未授权访问风险。",
                "recommendation": "配置MongoDB认证，限制访问IP，使用强密码，并禁用默认端口。"
            })
            
            # 尝试无密码连接测试
            try:
                import pymongo
                client = pymongo.MongoClient(f"mongodb://{target}:27017/", serverSelectionTimeoutMS=2000)
                client.server_info()  # 这将引发异常如果认证失败
                
                # 如果能连接，尝试列出数据库
                database_names = client.list_database_names()
                vulnerabilities.append({
                    "name": "MongoDB未授权访问",
                    "severity": "critical",
                    "description": f"成功无密码访问MongoDB服务器，并列出{len(database_names)}个数据库。",
                    "recommendation": "立即启用MongoDB认证，设置管理员密码，限制远程访问。"
                })
            except ImportError:
                print("缺少pymongo模块，跳过MongoDB未授权访问测试")
            except Exception as e:
                if "Authentication failed" not in str(e):
                    print(f"MongoDB连接测试错误: {str(e)}")
        except Exception as e:
            print(f"MongoDB漏洞检查错误: {str(e)}")

    def _check_redis_vulnerabilities(self, target, vulnerabilities):
        """检查Redis漏洞"""
        try:
            vulnerabilities.append({
                "name": "Redis服务暴露",
                "severity": "high",
                "description": "检测到目标系统开放了Redis缓存服务(端口6379)，可能存在未授权访问风险。",
                "recommendation": "配置Redis认证密码，限制只允许本地访问，或使用防火墙限制访问IP。"
            })
            
            # 尝试无密码连接测试
            try:
                import redis
                r = redis.Redis(host=target, port=6379, socket_timeout=2)
                info = r.info()  # 尝试获取Redis信息
                
                vulnerabilities.append({
                    "name": "Redis未授权访问",
                    "severity": "critical",
                    "description": f"成功无密码访问Redis服务器，可以执行任意命令。Redis版本: {info.get('redis_version', '未知')}",
                    "recommendation": "立即设置Redis认证密码，配置bind地址，禁用危险命令。"
                })
            except ImportError:
                print("缺少redis模块，跳过Redis未授权访问测试")
            except Exception as e:
                if "Authentication" not in str(e):
                    print(f"Redis连接测试错误: {str(e)}")
        except Exception as e:
            print(f"Redis漏洞检查错误: {str(e)}")

    # ... 其他新的漏洞检测方法 ... 
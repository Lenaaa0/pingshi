from typing import List, Dict, Optional, Any
from datetime import datetime
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

class SecurityScanner:
    def __init__(self):
        # 存储扫描结果的内存字典
        self._scan_results = {}
        
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
    
    def _perform_vulnerability_scan(self, result_id: str, target: str):
        """执行基本的漏洞扫描"""
        result = self._scan_results.get(result_id)
        if not result:
            return
        
        try:
            print(f"开始漏洞扫描: {target}")
            # 解析目标地址
            try:
                ip = socket.gethostbyname(target)
                print(f"目标IP: {ip}")
            except socket.gaierror:
                raise ValueError(f"无法解析目标地址: {target}")
            
            vulnerabilities = []
            
            # 使用requests库直接检查HTTP可用性
            http_available = False
            http_base_url = f"http://{target}"
            try:
                import requests
                # 禁用警告
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                response = requests.get(http_base_url, timeout=5, verify=False)
                print(f"HTTP连接成功，状态码: {response.status_code}")
                http_available = True
            except Exception as e:
                print(f"HTTP连接失败: {str(e)}")
            
            # 检查HTTPS可用性
            https_available = False
            https_base_url = f"https://{target}"
            try:
                response = requests.get(https_base_url, timeout=5, verify=False)
                print(f"HTTPS连接成功，状态码: {response.status_code}")
                https_available = True
            except Exception as e:
                print(f"HTTPS连接失败: {str(e)}")
            
            # 如果HTTP和HTTPS都不可用，尝试使用不同的User-Agent
            if not http_available and not https_available:
                try:
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    }
                    response = requests.get(http_base_url, headers=headers, timeout=5, verify=False)
                    print(f"使用自定义User-Agent的HTTP连接成功，状态码: {response.status_code}")
                    http_available = True
                except Exception as e:
                    print(f"使用自定义User-Agent的HTTP连接失败: {str(e)}")
            
            # 检查Web漏洞
            if http_available:
                print(f"检查Web漏洞: {http_base_url}")
                self._check_web_vulnerabilities(http_base_url, vulnerabilities)
            
            if https_available:
                print(f"检查Web漏洞: {https_base_url}")
                self._check_web_vulnerabilities(https_base_url, vulnerabilities)
            
            # 计算风险评分
            risk_score = self._calculate_risk_score([], vulnerabilities)
            
            # 生成摘要
            summary = f"扫描完成。在 {target} 上发现 {len(vulnerabilities)} 个安全漏洞。"
            
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
                open_ports=None,
                risk_score=risk_score
            )
            
            self._scan_results[result_id] = updated_result
            
        except Exception as e:
            print(f"漏洞扫描错误: {str(e)}")
            traceback.print_exc()  # 打印完整的堆栈跟踪
            # 更新为失败状态
            updated_result = ScanResult(
                id=result.id,
                scan_id=result.scan_id,
                target=result.target,
                scan_type=result.scan_type,
                start_time=result.start_time,
                end_time=datetime.now(),
                status="failed",
                summary=f"漏洞扫描失败: {str(e)}"
            )
            self._scan_results[result_id] = updated_result
    
    def _check_web_vulnerabilities(self, base_url, vulnerabilities):
        """检查Web漏洞"""
        # 检查SQL注入
        self._check_sql_injection(base_url, vulnerabilities)
        
        # 检查XSS漏洞
        self._check_xss_vulnerability(base_url, vulnerabilities)
        
        # 检查目录遍历
        self._check_directory_traversal(base_url, vulnerabilities)
        
        # 检查敏感文件
        self._check_sensitive_files(base_url, vulnerabilities)
    
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
                    
                    import requests
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
                    
                    import requests
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
                        import requests
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
                    import requests
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
                    import requests
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
        """扫描目标的漏洞"""
        print(f"开始漏洞扫描: {target}")
        
        # 模拟漏洞扫描结果
        # 实际应用中，这里应该调用真实的漏洞扫描工具
        await asyncio.sleep(2)  # 模拟扫描耗时
        
        return [
            {
                "name": "示例漏洞 1",
                "severity": "高",
                "description": "这是一个示例漏洞描述",
                "recommendation": "这是修复建议"
            },
            {
                "name": "示例漏洞 2",
                "severity": "中",
                "description": "另一个示例漏洞描述",
                "recommendation": "另一个修复建议"
            }
        ]

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
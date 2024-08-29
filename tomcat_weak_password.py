import logging
import requests
from requests.auth import HTTPBasicAuth
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import os

# 忽略不安全请求的警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

# 读取用户名列表
def load_usernames(file_path):
    if not os.path.isfile(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []
    with open(file_path, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]

# 读取密码列表
def load_passwords(file_path):
    if not os.path.isfile(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []
    with open(file_path, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]

# 读取URL列表
def load_urls(file_path):
    if not os.path.isfile(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []
    with open(file_path, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]

# 检测函数
def check_weak_password(url, usernames, passwords, output_file):
    for username in usernames:
        for password in passwords:
            try:
                response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=5, verify=False)
                response.encoding = 'utf-8'  # 确保使用 utf-8 编码处理响应
                if response.status_code == 200:
                    success_entry = f"{url} {username}:{password}"
                    logger.info(f"{Fore.RED}[+] 登录成功 {success_entry}{Style.RESET_ALL}")
                    with open(output_file, 'a', encoding='utf-8') as f:
                        f.write(success_entry + "\n")
                    return (url, username, password)  # 停止进一步的尝试
                else:
                    logger.info(f"{Fore.GREEN}[-] 失败: {username}:{password} {Fore.WHITE}({response.status_code}) {Fore.BLUE}{url}{Style.RESET_ALL}")
            except requests.exceptions.RequestException as e:
                logger.warning(f"{Fore.YELLOW}[!] 错误在 {url}: {str(e)}{Style.RESET_ALL}")
    return (url, None, None)

# 批量检测函数
def check_urls_in_threads(urls, usernames, passwords, max_workers, output_file):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(check_weak_password, url, usernames, passwords, output_file): url for url in urls}

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                future.result()
            except Exception as exc:
                logger.error(f"{url} 生成异常: {exc}")

if __name__ == "__main__":
    # 设置文件路径
    user_file = 'user.txt'
    passwd_file = 'passwd.txt'
    url_file = 'urls.txt'
    output_file = 'success.txt'

    # 加载用户名、密码和URL列表
    usernames = load_usernames(user_file)
    passwords = load_passwords(passwd_file)
    urls = load_urls(url_file)

    if not usernames or not passwords or not urls:
        logger.error("用户名、密码或URL列表为空，请检查文件")
    else:
        # 设置线程池大小
        max_workers = 100
        logger.info(f"开始检测当前线程 {max_workers} ...")

        # 执行并发检测
        check_urls_in_threads(urls, usernames, passwords, max_workers, output_file)

# TomcatWeakPassChecker

## 简介

该脚本用于检查Apache Tomcat管理页面的弱密码，并尝试通过上传自定义WAR包部署Godzilla Webshell。如果成功，将记录成功登录的信息以及获取到的Webshell地址。

## 功能

1. **弱密码检测**：根据提供的用户名和密码列表，检查目标URL是否存在弱密码。
2. **WAR文件生成**：生成包含Godzilla Webshell的WAR文件，并上传至目标服务器。
3. **Webshell获取**：上传成功后，尝试访问Webshell并记录URL。
4. **多线程支持**：支持用户自定义线程池大小，自动根据用户名和密码组合数量调整线程数。

Starred多后续考虑添加tomcat 文件上传 (CVE-2017-12615)、tomcat 代码执行 (CVE-2020-1938)等漏洞检测

## 依赖模块

在使用本脚本前，需要确保安装以下Python依赖模块：

- `requests`
- `colorama`
- `beautifulsoup4`

你可以通过以下命令安装所需模块：

```bash
pip install -r requirements.txt
```

## 使用方法

1. **准备文件**：

   - `user.txt`：包含要尝试的用户名列表，每行一个用户名。
   - `passwd.txt`：包含要尝试的密码列表，每行一个密码。
   - `urls.txt`：包含要检查的Tomcat管理页面URL列表，每行一个URL。

2. **运行脚本**：

   运行脚本时，用户名、密码和URL列表文件应放在与脚本相同的目录下。你可以通过命令行运行该脚本：

   ```
   python TomcatWeakPassChecker2.0.py
   ```

   用户可以在脚本中调整最大线程数和最小线程数以控制并发检测的速度和性能：

   ```
   max_workers_limit = 100  # 用户定义的最大线程数
   min_workers = 10  # 用户定义的最小线程数
   ```

3、**查看结果**：

脚本运行后，将会在`success.txt`文件中记录成功的登录信息和Webshell的URL。

## 注意事项

- **法律合规**：本脚本仅限于在获得授权的情况下进行安全测试。使用本脚本对未经授权的系统进行测试是非法的，并可能导致法律后果。
- **环境配置**：确保`shell.jsp`文件存在于脚本同目录下，用于生成WAR文件。
- **网络环境**：在网络不稳定或目标服务器响应慢的情况下，可以调整最大重试次数和线程池大小以获得更好的结果。

## 示例

假设你有如下文件：

- `user.txt` 包含以下内容：

   ```
   admin
   tomcat
   ```

- `passwd.txt` 包含以下内容：

   ```
   admin
   tomcat
   123456
   ```

`urls.txt` 包含以下内容：

   ```
   http://example.com/manager/html
   ```

运行脚本后，将尝试在 `http://example.com/manager/html` 使用 `user.txt` 和 `passwd.txt` 中的组合进行登录，并记录成功的结果。

![QQ20240902-165901](https://github.com/user-attachments/assets/f920d41c-1427-489f-9b34-eb649160bd12)


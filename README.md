# TomcatWeakPassChecker

## 简介

该脚本用于检查Apache Tomcat管理页面的弱密码，并尝试通过上传自定义WAR包部署Webshell。如果成功，将记录成功登录的信息以及获取到的Webshell地址。

## 功能

1. **弱密码检测**：根据提供的用户名和密码列表，检查目标URL是否存在弱密码。
2. **WAR文件生成**：生成包含Webshell的WAR文件，并上传至目标服务器。
3. **Webshell获取**：上传成功后(默认Godzilla马)，尝试访问Webshell并记录URL。
4. **多线程支持**：动态调整线程池大小，确保资源使用合理。
5. **配置灵活**：通过配置文件设置重试次数、重试间隔和线程池大小、webshell，适应不同的环境需求。

Starred多后续考虑添加tomcat 文件上传 (CVE-2017-12615)、tomcat 代码执行 (CVE-2020-1938)等漏洞检测

## 环境安装

通过以下命令安装所需模块：

```bash
pip install -r requirements.txt
```

## 使用方法

1. 准备包含URL、用户名和密码的文本文件，分别命名为`urls.txt`、`user.txt`和`passwd.txt`。
2. 在`config.yaml`中配置文件路径和其他设置。
3. 运行脚本，将会在`success.txt`文件中记录成功的登录信息和Webshell的URL。

   ```
   python TomcatWeakPassChecker2.1.py
   ```


## 注意事项

- 使用此脚本时请遵守相关法律法规，不要进行未授权的操作。
- 本脚本仅供教育和测试用途，不承担任何由不当使用造成的后果。

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


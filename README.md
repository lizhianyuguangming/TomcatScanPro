# TomcatWeakPassChecker

## 简介

本项目是一个针对 **Tomcat** 服务的弱口令检测和 **CVE-2017-12615** 漏洞检测工具。通过该工具，您可以检测 Tomcat 的弱口令，并利用 **CVE-2017-12615** 漏洞上传并执行 WebShell。同时，工具支持通过后台部署 `WAR` 包的方式进行 `getshell` 操作。该工具支持对多个 URL 进行并发检测，并通过线程池管理资源使用，提升检测效率。

## 功能

### 1. **CVE-2017-12615 漏洞检测**
   - 工具支持三种利用方式：
     1. `PUT /<filename>.jsp/`
     2. `PUT /<filename>.jsp%20`
     3. `PUT /<filename>.jsp::$DATA`
   - 成功上传后，工具会尝试访问并执行上传的 JSP 文件，判断是否能远程执行代码。
   - 对每种利用方式的结果分别记录成功或失败状态。

### 2. **弱口令检测**
   - 支持通过用户名与密码组合进行弱口令暴力破解。
   - 若登录成功，将自动尝试上传 Godzilla Webshell，提供远程访问能力。
   - 登录成功与否均会详细记录。

### 3. **后台部署 WAR 包 `getshell`**
   - 在弱口令破解成功后，工具会尝试通过 Tomcat 管理后台上传 `WAR` 包，以获取远程代码执行权限。
   - 部署的 `WAR` 包会在服务器上解压并生成 JSP Shell 文件，成功上传后，工具会访问并执行该 Shell。
   - 支持通过配置文件自定义 `WAR` 包和 Shell 文件的内容。

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
   python TomcatWeakPassChecker.py
   ```


![QQ20240902-165901](https://github.com/user-attachments/assets/f920d41c-1427-489f-9b34-eb649160bd12)


## 注意事项

- 使用此脚本时请遵守相关法律法规，不要进行未授权的操作。
- 本脚本仅供教育和测试用途，不承担任何由不当使用造成的后果。



**使用有什么问题或改进想法，在Issues提出**

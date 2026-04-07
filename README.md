# Thu Network AutoAuth

Thu Network AutoAuth 是一个自动连接清华大学校园网的工具，运行时将扫描指定 ip 地址的可达性和该地址在清华大学校园网自服务平台的在线状态，若 ip 地址可达但未在线，则通过自服务平台的准入代认证接口对该地址进行认证。

由于清华大学校园网自服务平台的登录和认证需要给出清华大学用户电子身份的密码，因此 Thu Network AutoAuth 会将密码保存在系统的安全存储中（如 Windows Credential Manager、macOS Keychain 或 Linux Secret Service），使用本工具即代表同意将密码保存在系统当前用户的安全存储中。

## 安装

通过 pip 安装：

```bash
pip install thu-network-autoauth
```

## 使用

在开始使用前，请先运行以下命令设置密码和配置：

```bash
thu-auth --config
thu-auth --password
```

无参数运行将启动自动认证服务：

```bash
thu-auth
```

配置文件和日志文件地址将在运行后打印到控制台，其中配置文件格式如下：
```yaml
account: username           # 清华大学用户电子身份用户名

password:
  service_name: thu-auth    # 密码在系统安全存储中的服务名称

devices:
  - 192.168.1.100           # 需要监控的 IP 地址列表
  - 192.168.1.101

monitor:
  check_interval: 60        # 两次扫描之间的时间间隔，单位为秒
```

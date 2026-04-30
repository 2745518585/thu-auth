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

config:
  allow_webvpn: true        # 是否允许通过 WebVPN 进行认证（适用于设备在校外等无法直接访问自服务平台的情况）
  requests_timeout: 2       # 进行网络请求时的超时时间，单位为秒
  monitor_interval: 60      # 两次扫描之间的时间间隔，单位为秒
```

### WebVPN

开启允许通过 WebVPN 进行认证后，当本工具检测到无法直接访问自服务平台时，将自动通过 WebVPN 进行认证。

> [!IMPORTANT]
> 访问 WebVPN 需要通过清华大学用户电子身份系统进行认证，因此直接访问可能会因为处于未信任环境中被要求进行二次认证，用户需要通过输入已信任环境的指纹（fingerPrint）来允许本工具通过二次认证。开启允许通过 WebVPN 进行认证功能将要求用户提供一个已信任环境的指纹以供认证使用。

已信任环境的指纹可以来自常用浏览器环境或自行生成并进行至少一次认证，建议使用来自常用浏览器环境的指纹，以便在认证过期后可以及时发现并重新认证。

用户可以按照以下步骤获取浏览器的指纹：
1. 访问 [清华大学用户电子身份系统](https://id.tsinghua.edu.cn/) 的登录界面，如果已经登录，请先退出登录。
2. 打开浏览器的开发者工具，在保持开发者工具打开的状态下进行登录操作。
3. 切换到开发者工具的网络（Network）面板，找到目标为 `/security_check` 的请求，在负载（Payload）部分找到 `fingerPrint` 字段，其中的 32 位十六进制字符串即为指纹。

运行以下命令以设置指纹：

```bash
thu-auth --fingerprint
```

## 许可证

Thu Network AutoAuth 使用 MIT 许可证，详情请参阅 [LICENSE](LICENSE) 文件。

本项目所有依赖项的许可证信息请参阅 [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES.md) 文件，该文件由 pip-licenses 自动生成。

## 声明

本工具仅用于校园网络自动化连接与学习用途，用户应确保在使用本工具时遵守清华大学校园网的相关规定和政策。开发者不对因使用本工具而导致的任何网络安全问题或账户安全问题负责。用户在使用本工具前应充分了解相关风险，并自行承担使用本工具可能带来的后果。

# 维兰德公国 · 政务模拟终端（Vidland）

> 这是一个**虚构公国**的政务 / 安检角色扮演网页应用，定位是**游戏与模拟器**，**不是任何真实国家或政府系统**。

## 关于 AI 辅助

本项目在 AI 编程助手全程协助下完成：界面与交互逻辑、政务申请表单与加密登记册、六语词库、本地存档方案等，均由人工设定方向与边界、AI 协作生成并打磨。它既适合作为「AI 辅助开发」的一个示例，也欢迎在其之上继续改造。

## 它是什么 / 能用来做什么

维兰德公国是一个架空的微型主权实体。这套终端把「入境—境内—管理」的政务流程做成了可在浏览器里直接运行的模拟器，主要用途是：

- **桌面角色扮演（TTRPG）/ 跑团道具**：GM 与玩家可用它递交、审核、签发各类申请与许可。
- **世界构建与推演**：把一套自洽的行政法规、安检分级（R / Z / A / M）、密文登记册跑起来，作为设定集的活道具。
- **前端原型 / 教学示例**：纯静态、无框架、四端同源，方便拆解学习。

## 四个终端（四端同源）

| 终端 | 说明 |
| --- | --- |
| 门户 Civil Affairs Portal | 申请、表单、登记册查看 |
| 入境安检 Frontier Inspection（R 级） | 边境入境审查 |
| 境内安检 Interior Inspection（Z / A / M 级） | 境内分级审查 |
| 管理端 Chancellery Authority | 审核、签发、统计 |

## 技术说明

- **纯静态**：HTML + CSS + 原生 JS，无构建步骤。
- **本地存档**：申请表草稿与加密登记册默认写入本机真实文件（`store.json`）。首次使用需在浏览器中授权一个文件夹（Chrome / Edge，走 `http://localhost`）。
- **可选静态服务**：`python serve.py` 仅用于在本机起一个静态服务来加载页面；存档本身不依赖它长驻。它也提供加密登记册的读写接口，供不支持文件夹授权的浏览器（如手机、Firefox）使用。
- **六语界面**：内置词库支持多语言切换。

## 局域网访问（手机 / 平板）

把电脑当作服务器，让同一 WiFi 下的移动设备访问。存档仍然写在**电脑本机**，各设备通过轮询服务端版本号实时同步。

**为什么必须用 HTTPS**：浏览器只允许在安全上下文（`https://` 或 `localhost`）里使用加密接口。用 `http://192.168.x.x` 这种局域网 IP 访问时，`crypto.subtle` 不可用，整个加密登记册会失效。

### 一键启用

```
python quickstart.py lan
```

等价的手动方式：

```
python make_cert.py
VDL_LAN=1 python serve.py
```

`VDL_LAN=1` 会自动开启 TLS 并绑定 `0.0.0.0`。未设置时行为与原来完全一致（本机纯 HTTP）。

### 手机端两步

1. 在同一 WiFi 下打开控制台打印的 `https://192.168.x.x:7431/ca.pem`，下载并安装根证书。
   - Android：设置里安装为「VPN 与应用的 CA 证书」。
   - iOS：Safari 打开后会提示安装描述文件，再到「设置 → 通用 → 关于本机 → 证书信任设置」开启完全信任。
2. 打开 `https://192.168.x.x:7431/index.html`。装好根证书后不会有安全警告。

证书由 `make_cert.py` 生成，包含 `localhost`、回环地址和本机所有网卡 IP；换 IP 后重跑 `python make_cert.py --force` 并重新在手机上安装根证书即可。也可以用 `VDL_LAN_IP` 指定额外 IP，或用 `VDL_LAN_DNS` 追加域名。所有证书与私钥都放在 `vidland-data/`，该目录已被忽略，不会进入仓库。

如果手机连不上，需要放行 Windows 防火墙的 TCP 7431 入站（专用网络）：

```
netsh advfirewall firewall add rule name="Vidland LAN 7431" dir=in action=allow protocol=TCP localport=7431 profile=private,domain
```

### 两点安全说明

- `admin.html` 内含解密申请材料所需的私钥，因此**局域网模式下管理端只对本机开放**，其他设备访问会返回 403。确需放开用 `VDL_ADMIN_LAN=1`，但不建议。
- 服务端只提供四个 HTML、三个 JS、一个 CSS 和 `/ca.pem`；`vidland-data/`（含私钥与密文档案）、`.git/`、`.py` 文件都不可下载。
- 证书是本地自签的。若希望手机**完全免配置**，可改用自有域名 + Let's Encrypt（DNS-01 挑战）签发的证书，把 A 记录指向内网 IP，再用 `VDL_CERT` / `VDL_KEY` 指定证书路径即可，服务端代码无需改动。

## 使用截图

![门户](screenshots/index.png)

![入境安检](screenshots/border.png)

![境内安检](screenshots/interior.png)

![管理端](screenshots/admin.png)

## 快速开始

1. 在项目目录运行 `python serve.py`（默认端口 7431）。
2. 用 **Chrome 或 Edge** 打开 `http://127.0.0.1:7431/index.html`（请走 localhost，不要用 `file://` 直接双击打开）。
3. 首次进入后点击页面任意位置，按提示选择一个文件夹用于存放存档（建议选项目内的 `vidland-data`），之后存档直接落盘，四端实时同步。

若要在手机等局域网设备上使用，改看上面的「局域网访问」一节：运行 `python quickstart.py lan`，手机通过 `https://` 访问时会自动改用共享的服务端存档（移动端不支持文件夹授权）。

## 许可证

本项目以 [Apache License 2.0](LICENSE) 发布。

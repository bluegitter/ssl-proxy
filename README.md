# ssl-proxy

## 项目简介

`ssl-proxy` 是一个支持 HTTPS 的高性能反向代理服务器，适合本地开发、内网服务加密、微服务网关等场景。支持多路由分发、静态资源服务、自动生成自签名证书、LetsEncrypt 证书等功能。

## 主要功能
- 支持多路由反向代理（按 Host、Path、Host+Path 分发）
- 支持静态资源目录服务，可与路由代理共存
- 自动生成自签名根证书和私钥，支持自定义证书组织、DNS、IP
- 支持 LetsEncrypt 自动签发证书
- 支持 HTTP 自动跳转到 HTTPS
- 支持通过 JSON 文件或命令行参数配置路由

## 安装与编译

### 直接下载
前往 [Releases](https://github.com/suyashkumar/ssl-proxy/releases) 下载适合你系统的二进制文件。

### 源码编译
```bash
git clone https://github.com/suyashkumar/ssl-proxy.git
cd ssl-proxy
make build
```
编译后生成 `ssl-proxy` 可执行文件。

## 命令行参数说明

| 参数           | 说明                                                                                 |
|----------------|--------------------------------------------------------------------------------------|
| -from          | 监听的本地地址和端口（如 0.0.0.0:4430）                                              |
| -to            | 默认反向代理目标地址（如 http://127.0.0.1:8000），与 -root 不能同时使用               |
| -routers       | 路由规则，格式为 /path=target 或 host=/path=target，多个用逗号分隔                   |
| -routersFile   | 路由规则 JSON 文件或 JSON 字符串                                                     |
| -root          | 静态资源目录，未命中路由时返回静态文件，与 -to 不能同时使用                          |
| -cert          | 证书文件路径，默认 cert.pem，不存在时自动生成                                        |
| -key           | 私钥文件路径，默认 key.pem，不存在时自动生成                                         |
| -certOrg       | 证书组织（Organization），默认 ssl-proxy                                            |
| -certDNS       | 证书 DNS 名称，多个用逗号分隔，默认 localhost                                       |
| -certIP        | 证书 IP 地址，多个用逗号分隔，默认空                                                |
| -domain        | 使用 LetsEncrypt 自动签发证书时指定域名                                              |
| -redirectHTTP  | 是否自动将 80 端口的 HTTP 跳转到 HTTPS                                               |

## 常用示例

### 1. 仅反向代理单一目标
```bash
./ssl-proxy -from 0.0.0.0:4430 -to http://127.0.0.1:8000
```

### 2. 多路由分发
```bash
./ssl-proxy -from 0.0.0.0:4430 -routers "/api=http://127.0.0.1:8001,/img=http://127.0.0.1:8002"
```

### 3. 路由+静态资源服务
```bash
./ssl-proxy -from 0.0.0.0:4430 -routers "/api=http://127.0.0.1:8001" -root ./html
```

### 4. 使用 JSON 文件配置路由
`routers.json` 内容：
```json
[
  {"host": "a.com", "target": "http://127.0.0.1:8001"},
  {"path": "/api2", "target": "http://127.0.0.1:8002"},
  {"host": "b.com", "path": "/foo", "target": "http://127.0.0.1:8003"}
]
```
命令：
```bash
./ssl-proxy -from 0.0.0.0:4430 -routersFile routers.json
```

### 5. 自定义证书组织、DNS、IP
```bash
./ssl-proxy -from 0.0.0.0:4430 \
  -certOrg "MyCompany" \
  -certDNS "mydomain.com,localhost" \
  -certIP "127.0.0.1,192.168.1.100"
```

### 6. 自动生成自签名证书
首次运行时如 `cert.pem` 或 `key.pem` 不存在会自动生成。

### 7. 让 macOS 信任自签名根证书
1. 打开“钥匙串访问”，选择“系统”钥匙串。
2. 导入 `cert.pem`，双击证书，展开“信任”，设置为“始终信任”。
3. 输入管理员密码，重启浏览器。

或命令行：
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.pem
```

## 常见问题

- **证书不被信任？**
  - 请按上面“让 macOS 信任自签名根证书”操作。
- **导入证书报错 -26276？**
  - 检查 `cert.pem` 是否为标准 PEM 格式，只包含证书内容。
- **-root 和 -to 不能同时用？**
  - 只能二选一。
- **如何让未命中路由的请求有默认后端？**
  - 配置 -to 或 -root。

---

如有更多问题请提交 issue 或联系作者。

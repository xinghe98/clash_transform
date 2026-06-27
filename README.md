# Clash Transform

把机场/代理订阅链接转换成一份可直接导入 OpenClash、Clash Verge、Mihomo Party 等客户端的 YAML 配置。

脚本会以 `example.cofig.yaml` 为模板，保留里面的端口、DNS、分组、规则和 `rule-providers`，只替换订阅中的节点，并自动修正规则链接。

## 文件说明

- `transform.py`：转换脚本
- `example.cofig.yaml`：配置模板
- `config.yaml`：默认生成的输出文件
- `ruleset/`：使用 `--update-rules` 时下载 `.mrs` 规则文件的位置

## 环境要求

- Python 3.9 或更高版本
- PyYAML

安装依赖：

```bash
pip install pyyaml
```

如果你电脑上同时有多个 Python 版本，也可以用：

```bash
python -m pip install pyyaml
```

## 基本使用

在当前目录运行：

```bash
python transform.py "你的订阅链接"
```

默认会生成：

```text
config.yaml
```

指定输出文件：

```bash
python transform.py "你的订阅链接" -o openclash.yaml
```

合并多个订阅到同一个配置：

```bash
python transform.py "订阅链接1" "订阅链接2" "订阅链接3" -o merged.yaml
```

脚本会合并所有订阅里的节点，并按节点类型、服务器、端口、UUID/密码自动去重。

指定模板文件：

```bash
python transform.py "你的订阅链接" -t example.cofig.yaml -o config.yaml
```

## OpenClash 推荐用法

推荐直接使用默认命令：

```bash
python transform.py "你的订阅链接" -o config.yaml
```

然后在 OpenClash 中导入 `config.yaml`。

默认情况下，脚本会把模板里的 `include-all`、`filter`、`exclude-filter` 展开成明确的节点列表。这样兼容性更好，避免部分 OpenClash/Clash 内核不完整支持 Mihomo 扩展字段导致分组为空。

脚本还会根据订阅节点名自动生成实际存在的国家/地区分组。例如订阅里有香港、日本、英国、马来西亚节点，就只生成这些地区分组；没有韩国节点时不会生成韩国空分组，避免 ProxyGroup 循环。

## Mihomo 专用模式

如果你只使用 Mihomo，并且希望保留模板中的 `include-all`、`filter`、`exclude-filter`，可以加：

```bash
python transform.py "你的订阅链接" --keep-include-all
```

这种模式更依赖 Mihomo 的扩展能力，不建议用于老版本 Clash 或兼容性不确定的 OpenClash 配置。

## 规则更新逻辑

默认转换时会更新 YAML 里的 `rule-providers` 链接，但不会下载规则文件。

也就是说，生成的配置中会包含类似这样的规则源：

```yaml
rule-providers:
  google:
    type: http
    behavior: domain
    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/google.mrs
    path: ./ruleset/google.mrs
    interval: 86400
    format: mrs
```

Clash/Mihomo/OpenClash 会根据 `interval` 自动下载和更新规则。

如果你想在转换时同时把 `.mrs` 规则文件下载到本地：

```bash
python transform.py "你的订阅链接" --update-rules
```

## 支持的订阅格式

- Clash/Mihomo YAML 订阅
- Base64 文本订阅
- `ss://`
- `vmess://`
- `trojan://`
- `vless://`
- `hysteria2://` / `hy2://`

## 自动处理内容

- 替换模板中的 `proxies`
- 保留模板中的 `dns`、`proxy-groups`、`rule-providers`、`rules`
- 过滤流量、套餐、到期、官网等信息节点
- 自动去重重复节点
- 自动处理重复节点名
- 自动规范化规则链接
- 检查 `rules` 引用的 `rule-providers` 是否存在
- 根据订阅节点名自动生成实际存在的国家/地区分组
- 默认展开区域分组，提升 OpenClash 兼容性并避免空地区分组循环

## 参数说明

| 参数 | 说明 |
| --- | --- |
| `subscriptions` | 必填，一个或多个订阅链接 |
| `-o, --output` | 输出文件，默认 `config.yaml` |
| `-t, --template` | 模板文件，默认 `example.cofig.yaml` |
| `--update-rules` | 转换时下载 `.mrs` 规则文件 |
| `--keep-include-all` | 保留 Mihomo 的 `include-all` 分组写法 |
| `--user-agent` | 请求订阅时使用的 User-Agent，默认 `clash.meta` |

## 常见问题

### 提示 `Missing dependency: PyYAML`

安装依赖：

```bash
pip install pyyaml
```

### 提示 `No supported proxy nodes found in subscription`

说明订阅内容没有识别到支持的节点。可能原因：

- 订阅链接需要登录或已经过期
- 订阅返回的是网页，不是配置内容
- 节点协议暂不支持
- 网络无法访问订阅地址
- 订阅服务按 User-Agent 分流，当前 User-Agent 返回了空配置

可以尝试指定 User-Agent：

```bash
python transform.py "你的订阅链接" --user-agent clash.meta
```

或：

```bash
python transform.py "你的订阅链接" --user-agent "ClashForWindows/0.20.39"
```

### OpenClash 导入后分组为空

不要加 `--keep-include-all`，使用默认模式重新生成：

```bash
python transform.py "你的订阅链接" -o config.yaml
```

默认模式会把节点明确写入分组，兼容性更好。

### 规则下载失败

默认不需要提前下载规则文件。只要配置中的 `rule-providers` URL 可访问，OpenClash/Mihomo 会自己更新。

如果你使用了 `--update-rules`，下载失败通常是网络访问 GitHub raw 链接失败。可以不加该参数重新生成配置。

## 示例

生成 OpenClash 配置：

```bash
python transform.py "https://example.com/sub" -o config.yaml
```

合并多个订阅：

```bash
python transform.py "https://example.com/sub1" "https://example.com/sub2" -o merged.yaml
```

生成 Mihomo 配置并保留 `include-all`：

```bash
python transform.py "https://example.com/sub" -o mihomo.yaml --keep-include-all
```

生成配置并下载规则文件：

```bash
python transform.py "https://example.com/sub" -o config.yaml --update-rules
```

#!/usr/bin/env python3
"""Convert a proxy subscription into a Clash/Mihomo config based on a template."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    print("缺少依赖：PyYAML。请先运行：pip install pyyaml", file=sys.stderr)
    raise SystemExit(1)


DEFAULT_TEMPLATE = "example.cofig.yaml"
DEFAULT_OUTPUT = "config.yaml"
DEFAULT_USER_AGENT = "clash.meta"
RULE_BASE = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta"
INFO_NODE_RE = re.compile(r"(?i)traffic|流量|套餐|到期|剩余|订阅|官网|expire|剩余流量|过期")
GEOIP_PROVIDER_FILES = {
    "private-ip": "private.mrs",
    "cn-ip": "cn.mrs",
    "google-ip": "google.mrs",
    "telegram-ip": "telegram.mrs",
    "twitter-ip": "twitter.mrs",
    "facebook-ip": "facebook.mrs",
    "netflix-ip": "netflix.mrs",
    "cloudflare-ip": "cloudflare.mrs",
}
REGION_DEFINITIONS = [
    ("🇭🇰 香港", re.compile(r"(?i)香港|港(?!口)|hk|hkg|hong\s*kong|hongkong")),
    ("🇲🇴 澳门", re.compile(r"(?i)澳门|澳門|mo|macau|macao")),
    ("🇹🇼 台湾", re.compile(r"(?i)台湾|台灣|台|tw|twn|taiwan")),
    ("🇯🇵 日本", re.compile(r"(?i)日本|日(?!志)|jp|jpn|japan|tokyo|osaka")),
    ("🇸🇬 新加坡", re.compile(r"(?i)新加坡|坡|狮城|獅城|sg|sgp|singapore")),
    ("🇺🇸 美国", re.compile(r"(?i)美国|美國|美|us|usa|united\s*states|america|los\s*angeles|la|san\s*jose|sjc|new\s*york|nyc")),
    ("🇰🇷 韩国", re.compile(r"(?i)韩国|韓國|韩|韓|kr|kor|korea|seoul")),
    ("🇬🇧 英国", re.compile(r"(?i)英国|英國|英|uk|gb|gbr|united\s*kingdom|britain|london")),
    ("🇩🇪 德国", re.compile(r"(?i)德国|德國|德|de|deu|ger|germany|frankfurt")),
    ("🇫🇷 法国", re.compile(r"(?i)法国|法國|法|fr|fra|france|paris")),
    ("🇳🇱 荷兰", re.compile(r"(?i)荷兰|荷蘭|荷|nl|nld|netherlands|holland|amsterdam")),
    ("🇨🇦 加拿大", re.compile(r"(?i)加拿大|加|ca|can|canada|toronto|vancouver")),
    ("🇦🇺 澳大利亚", re.compile(r"(?i)澳大利亚|澳大利亞|澳洲|澳|au|aus|australia|sydney|melbourne")),
    ("🇲🇾 马来西亚", re.compile(r"(?i)马来西亚|馬來西亞|大马|大馬|马来|馬來|my|mys|malaysia|kuala\s*lumpur|kl")),
    ("🇹🇭 泰国", re.compile(r"(?i)泰国|泰國|泰|th|tha|thailand|bangkok")),
    ("🇵🇭 菲律宾", re.compile(r"(?i)菲律宾|菲律賓|菲|ph|phl|philippines|manila")),
    ("🇮🇩 印度尼西亚", re.compile(r"(?i)印度尼西亚|印尼|id|idn|indonesia|jakarta")),
    ("🇮🇳 印度", re.compile(r"(?i)印度|in|ind|india|mumbai|delhi")),
    ("🇻🇳 越南", re.compile(r"(?i)越南|越|vn|vnm|vietnam")),
    ("🇹🇷 土耳其", re.compile(r"(?i)土耳其|土|tr|tur|turkey|istanbul")),
    ("🇦🇷 阿根廷", re.compile(r"(?i)阿根廷|阿根廷|ar|arg|argentina")),
    ("🇧🇷 巴西", re.compile(r"(?i)巴西|br|bra|brazil|sao\s*paulo")),
    ("🇲🇽 墨西哥", re.compile(r"(?i)墨西哥|mx|mex|mexico")),
    ("🇷🇺 俄罗斯", re.compile(r"(?i)俄罗斯|俄羅斯|俄|ru|rus|russia|moscow")),
    ("🇺🇦 乌克兰", re.compile(r"(?i)乌克兰|烏克蘭|ua|ukr|ukraine")),
]
REGION_GROUPS = dict(REGION_DEFINITIONS)
OTHER_REGION_GROUP = "🌍 其他地区"


class LiteralString(str):
    pass


class Dumper(yaml.SafeDumper):
    pass


def represent_literal(dumper: yaml.SafeDumper, data: LiteralString) -> yaml.Node:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


Dumper.add_representer(LiteralString, represent_literal)


def fetch_url(url: str, timeout: int = 30, user_agent: str = DEFAULT_USER_AGENT) -> tuple[bytes, dict[str, str]]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "*/*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            return response.read(), headers
    except urllib.error.URLError as exc:
        raise RuntimeError(f"下载失败：{exc}") from exc


def decode_text(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def b64decode_text(value: str) -> str:
    compact = "".join(value.strip().split())
    padding = "=" * (-len(compact) % 4)
    return base64.urlsafe_b64decode((compact + padding).encode()).decode("utf-8", errors="replace")


def maybe_base64_subscription(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return stripped
    if re.search(r"(?m)^\s*(proxies|proxy-providers|proxy-groups|rules)\s*:", stripped):
        return stripped
    if re.search(r"(?m)^\s*(ss|ssr|vmess|vless|trojan|hysteria2|hy2)://", stripped):
        return stripped
    try:
        decoded = b64decode_text(stripped)
    except Exception:
        return stripped
    if re.search(r"(?m)^\s*(ss|ssr|vmess|vless|trojan|hysteria2|hy2)://", decoded):
        return decoded
    return stripped


def parse_yaml_config(text: str) -> dict[str, Any] | None:
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if isinstance(loaded, dict) and isinstance(loaded.get("proxies"), list):
        return loaded
    return None


def parse_plugin_opts(query: dict[str, list[str]]) -> tuple[str | None, dict[str, Any] | None]:
    plugin_values = query.get("plugin")
    if not plugin_values:
        return None, None
    decoded = urllib.parse.unquote(plugin_values[0])
    parts = decoded.split(";")
    plugin = parts[0] if parts else None
    opts: dict[str, Any] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            opts[key] = value
        elif part:
            opts[part] = True
    return plugin, opts or None


def parse_ss(link: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(link)
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "ss"
    query = urllib.parse.parse_qs(parsed.query)

    userinfo = parsed.username
    server = parsed.hostname
    port = parsed.port
    if userinfo and ":" not in userinfo:
        try:
            decoded = b64decode_text(userinfo)
            method, password = decoded.split(":", 1)
        except ValueError as exc:
            raise ValueError("无效的 ss 用户信息") from exc
    elif userinfo:
        method = urllib.parse.unquote(userinfo)
        password = urllib.parse.unquote(parsed.password or "")
    else:
        raw = link[5:].split("#", 1)[0].split("?", 1)[0]
        decoded = b64decode_text(raw)
        method_password, address = decoded.rsplit("@", 1)
        method, password = method_password.split(":", 1)
        server, port_text = address.rsplit(":", 1)
        port = int(port_text)

    if not server or not port:
        raise ValueError("无效的 ss 服务器或端口")

    proxy: dict[str, Any] = {
        "name": name,
        "type": "ss",
        "server": server,
        "port": int(port),
        "cipher": method,
        "password": password,
        "udp": True,
    }
    plugin, plugin_opts = parse_plugin_opts(query)
    if plugin:
        proxy["plugin"] = plugin
    if plugin_opts:
        proxy["plugin-opts"] = plugin_opts
    return proxy


def parse_vmess(link: str) -> dict[str, Any]:
    payload = b64decode_text(link[len("vmess://") :])
    data = json.loads(payload)
    proxy: dict[str, Any] = {
        "name": data.get("ps") or data.get("name") or "vmess",
        "type": "vmess",
        "server": data["add"],
        "port": int(data["port"]),
        "uuid": data["id"],
        "alterId": int(data.get("aid") or 0),
        "cipher": data.get("scy") or data.get("cipher") or "auto",
        "udp": True,
    }
    network = data.get("net")
    if network:
        proxy["network"] = network
    tls = data.get("tls")
    if tls:
        proxy["tls"] = tls in ("tls", "true", True)
    servername = data.get("sni") or data.get("host")
    if servername and proxy.get("tls"):
        proxy["servername"] = servername
    if network == "ws":
        proxy["ws-opts"] = {
            "path": data.get("path") or "/",
            "headers": {"Host": data.get("host")} if data.get("host") else {},
        }
    return proxy


def parse_trojan_or_vless(link: str, kind: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(link)
    query = urllib.parse.parse_qs(parsed.query)
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else kind
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise ValueError(f"无效的 {kind} 链接")
    proxy: dict[str, Any] = {
        "name": name,
        "type": kind,
        "server": parsed.hostname,
        "port": int(parsed.port),
        "udp": True,
    }
    if kind == "trojan":
        proxy["password"] = urllib.parse.unquote(parsed.username)
    else:
        proxy["uuid"] = urllib.parse.unquote(parsed.username)
        flow = query.get("flow", [""])[0]
        if flow:
            proxy["flow"] = flow

    security = query.get("security", query.get("tls", [""]))[0]
    if security in ("tls", "reality"):
        proxy["tls"] = True
    if security == "reality":
        proxy["reality-opts"] = {}
        pbk = query.get("pbk", [""])[0]
        sid = query.get("sid", [""])[0]
        if pbk:
            proxy["reality-opts"]["public-key"] = pbk
        if sid:
            proxy["reality-opts"]["short-id"] = sid
    sni = query.get("sni", query.get("peer", [""]))[0]
    if sni:
        proxy["servername"] = sni
    network = query.get("type", query.get("network", [""]))[0]
    if network:
        proxy["network"] = network
    if network == "ws":
        host = query.get("host", [""])[0]
        proxy["ws-opts"] = {
            "path": query.get("path", ["/"])[0] or "/",
            "headers": {"Host": host} if host else {},
        }
    return proxy


def parse_hysteria2(link: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(link)
    query = urllib.parse.parse_qs(parsed.query)
    if not parsed.hostname or not parsed.port:
        raise ValueError("无效的 hysteria2 链接")
    proxy: dict[str, Any] = {
        "name": urllib.parse.unquote(parsed.fragment) if parsed.fragment else "hysteria2",
        "type": "hysteria2",
        "server": parsed.hostname,
        "port": int(parsed.port),
        "password": urllib.parse.unquote(parsed.username or query.get("password", [""])[0]),
    }
    sni = query.get("sni", [""])[0]
    if sni:
        proxy["sni"] = sni
    if query.get("insecure", [""])[0] in ("1", "true"):
        proxy["skip-cert-verify"] = True
    return proxy


def parse_link(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        if line.startswith("ss://"):
            return parse_ss(line)
        if line.startswith("vmess://"):
            return parse_vmess(line)
        if line.startswith("trojan://"):
            return parse_trojan_or_vless(line, "trojan")
        if line.startswith("vless://"):
            return parse_trojan_or_vless(line, "vless")
        if line.startswith("hysteria2://") or line.startswith("hy2://"):
            return parse_hysteria2(line)
    except Exception as exc:
        print(f"跳过不支持或损坏的节点：{line[:48]}...（{exc}）", file=sys.stderr)
    return None


def clean_proxies(proxies: list[Any]) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    used_names: dict[str, int] = {}
    seen_keys: set[tuple[Any, ...]] = set()
    for item in proxies:
        if not isinstance(item, dict):
            continue
        proxy = copy.deepcopy(item)
        name = str(proxy.get("name") or "node").strip()
        if not name or INFO_NODE_RE.search(name):
            continue
        key = (proxy.get("type"), proxy.get("server"), proxy.get("port"), proxy.get("uuid"), proxy.get("password"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        count = used_names.get(name, 0)
        used_names[name] = count + 1
        proxy["name"] = name if count == 0 else f"{name} {count + 1}"
        cleaned.append(proxy)
    return cleaned


def parse_subscription(text: str) -> list[dict[str, Any]]:
    normalized = maybe_base64_subscription(text)
    yaml_config = parse_yaml_config(normalized)
    if yaml_config is not None:
        return clean_proxies(yaml_config.get("proxies", []))
    proxies = [proxy for line in normalized.splitlines() if (proxy := parse_link(line))]
    return clean_proxies(proxies)


def rule_url(provider_name: str, provider: dict[str, Any]) -> str:
    behavior = provider.get("behavior")
    section = "geo/geoip" if behavior == "ipcidr" or provider_name.endswith("-ip") else "geo/geosite"
    filename = GEOIP_PROVIDER_FILES.get(provider_name) or Path(str(provider.get("path") or f"{provider_name}.mrs")).name
    if not filename.endswith(".mrs"):
        filename = f"{provider_name}.mrs"
    return f"{RULE_BASE}/{section}/{filename}"


def normalize_rule_providers(config: dict[str, Any]) -> None:
    providers = config.get("rule-providers")
    if not isinstance(providers, dict):
        return
    for name, provider in providers.items():
        if not isinstance(provider, dict):
            continue
        provider["type"] = "http"
        provider.setdefault("behavior", "domain")
        provider["url"] = rule_url(str(name), provider)
        provider["path"] = f"./ruleset/{Path(str(provider.get('path') or f'{name}.mrs')).name}"
        provider["interval"] = int(provider.get("interval") or 86400)
        provider["format"] = "mrs"


def validate_rule_references(config: dict[str, Any]) -> None:
    providers = config.get("rule-providers") or {}
    rules = config.get("rules") or []
    if not isinstance(providers, dict) or not isinstance(rules, list):
        return
    missing = []
    for rule in rules:
        if not isinstance(rule, str):
            continue
        parts = [part.strip() for part in rule.split(",")]
        if len(parts) >= 2 and parts[0] == "RULE-SET" and parts[1] not in providers:
            missing.append(parts[1])
    if missing:
        unique = ", ".join(sorted(set(missing)))
        raise RuntimeError(f"规则引用了不存在的 rule-providers：{unique}")


def group_has_include_all(group: dict[str, Any]) -> bool:
    return bool(group.get("include-all"))


def explicit_proxy_groups(config: dict[str, Any], proxies: list[dict[str, Any]]) -> None:
    groups = config.get("proxy-groups")
    if not isinstance(groups, list):
        return
    node_names = [proxy["name"] for proxy in proxies]
    regional_matches, other_nodes = detect_region_nodes(node_names)
    region_group_names = list(regional_matches)
    if other_nodes:
        region_group_names.append(OTHER_REGION_GROUP)
    old_region_names = set(REGION_GROUPS) | {OTHER_REGION_GROUP}

    first_region_index = next(
        (index for index, group in enumerate(groups) if isinstance(group, dict) and group.get("name") in old_region_names),
        len(groups),
    )
    insert_at = sum(
        1
        for group in groups[:first_region_index]
        if not (isinstance(group, dict) and str(group.get("name") or "") in old_region_names)
    )
    non_region_groups = [
        group for group in groups if not (isinstance(group, dict) and str(group.get("name") or "") in old_region_names)
    ]

    for group in non_region_groups:
        if not isinstance(group, dict):
            continue
        name = str(group.get("name") or "")
        current = group.get("proxies") if isinstance(group.get("proxies"), list) else []
        if group_has_include_all(group):
            group.pop("include-all", None)
            group.pop("filter", None)
            group.pop("exclude-filter", None)
            group["proxies"] = replace_region_refs(current, region_group_names, old_region_names)
            group["proxies"] = dedupe([*group["proxies"], *node_names])
        elif current:
            group["proxies"] = replace_region_refs(current, region_group_names, old_region_names)

    dynamic_region_groups = [{"name": name, "type": "select", "proxies": nodes} for name, nodes in regional_matches.items()]
    if other_nodes:
        dynamic_region_groups.append({"name": OTHER_REGION_GROUP, "type": "select", "proxies": other_nodes})

    config["proxy-groups"] = [
        *non_region_groups[:insert_at],
        *dynamic_region_groups,
        *non_region_groups[insert_at:],
    ]


def detect_region_nodes(node_names: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    matches: dict[str, list[str]] = {}
    matched_nodes: set[str] = set()
    for group_name, pattern in REGION_DEFINITIONS:
        nodes = [name for name in node_names if name not in matched_nodes and pattern.search(name)]
        if nodes:
            matches[group_name] = nodes
            matched_nodes.update(nodes)
    other_nodes = [name for name in node_names if name not in matched_nodes and not INFO_NODE_RE.search(name)]
    return matches, other_nodes


def replace_region_refs(items: list[Any], region_group_names: list[str], old_region_names: set[str]) -> list[Any]:
    result: list[Any] = []
    inserted_regions = False
    for item in items:
        if isinstance(item, str) and item in old_region_names:
            if not inserted_regions:
                result.extend(region_group_names)
                inserted_regions = True
            continue
        result.append(item)
    return dedupe(result)


def dedupe(items: list[Any]) -> list[Any]:
    result = []
    seen = set()
    for item in items:
        marker = str(item)
        if marker not in seen:
            seen.add(marker)
            result.append(item)
    return result


def display_subscription_source(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        tail = Path(parsed.path).name
        if tail:
            masked_tail = tail if len(tail) <= 10 else f"...{tail[-6:]}"
            return f"{parsed.netloc}/{masked_tail}"
        return parsed.netloc
    if parsed.scheme == "file":
        return f"file://{Path(parsed.path).name}"
    return url if len(url) <= 80 else f"{url[:32]}...{url[-16:]}"


def print_generation_summary(
    output_path: Path,
    subscriptions: list[str],
    subscription_counts: list[tuple[str, int]],
    proxies_before_merge: int,
    proxies: list[dict[str, Any]],
) -> None:
    node_names = [proxy["name"] for proxy in proxies]
    regional_matches, other_nodes = detect_region_nodes(node_names)
    region_names = list(regional_matches)
    if other_nodes:
        region_names.append(OTHER_REGION_GROUP)
    type_counts: dict[str, int] = {}
    for proxy in proxies:
        proxy_type = str(proxy.get("type") or "unknown")
        type_counts[proxy_type] = type_counts.get(proxy_type, 0) + 1

    print("\n转换摘要")
    print(f"  输出文件：{output_path}")
    print(f"  订阅数量：{len(subscriptions)}")
    for index, (source, count) in enumerate(subscription_counts, start=1):
        print(f"    {index}. {source}：{count} 个节点")
    print(f"  合并前节点数：{proxies_before_merge}")
    print(f"  去重后节点数：{len(proxies)}")
    print(f"  去除重复节点：{max(proxies_before_merge - len(proxies), 0)}")
    print(f"  国家/地区数量：{len(region_names)}")
    if region_names:
        print(f"    {', '.join(region_names)}")
    print(f"  协议类型：{', '.join(f'{name}={count}' for name, count in sorted(type_counts.items()))}")
    print("  规则处理：已规范化 rule-providers 链接；除非使用 --update-rules，否则不会下载本地规则文件")


def build_config(template_path: Path, proxies: list[dict[str, Any]], keep_include_all: bool) -> dict[str, Any]:
    with template_path.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)
    if not isinstance(config, dict):
        raise RuntimeError(f"模板不是有效的 YAML 映射：{template_path}")
    config["proxies"] = proxies
    normalize_rule_providers(config)
    validate_rule_references(config)
    if not keep_include_all:
        explicit_proxy_groups(config, proxies)
    return config


def download_rules(config: dict[str, Any], output_path: Path, user_agent: str) -> None:
    providers = config.get("rule-providers")
    if not isinstance(providers, dict):
        return
    base_dir = output_path.parent
    for name, provider in providers.items():
        if not isinstance(provider, dict):
            continue
        url = provider.get("url")
        path = provider.get("path")
        if not isinstance(url, str) or not isinstance(path, str):
            continue
        target = base_dir / path.replace("./", "")
        target.parent.mkdir(parents=True, exist_ok=True)
        data, _headers = fetch_url(url, user_agent=user_agent)
        target.write_bytes(data)
        print(f"已下载规则：{name} -> {target}")


def write_yaml(config: dict[str, Any], output_path: Path) -> None:
    text = yaml.dump(config, Dumper=Dumper, allow_unicode=True, sort_keys=False, default_flow_style=False)
    output_path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="基于 example.cofig.yaml 将订阅链接转换为 Clash/Mihomo/OpenClash YAML 配置")
    parser.add_argument("subscriptions", nargs="+", help="一个或多个订阅链接")
    parser.add_argument("-t", "--template", default=DEFAULT_TEMPLATE, help=f"模板 YAML 路径，默认：{DEFAULT_TEMPLATE}")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help=f"输出 YAML 路径，默认：{DEFAULT_OUTPUT}")
    parser.add_argument("--update-rules", action="store_true", help="转换时下载 rule-provider 的 .mrs 规则文件到本地 ruleset 目录")
    parser.add_argument("--keep-include-all", action="store_true", help="保留 Mihomo 专用的 include-all/filter 分组写法")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help=f"请求订阅时使用的 User-Agent，默认：{DEFAULT_USER_AGENT}")
    args = parser.parse_args()

    template_path = Path(args.template)
    output_path = Path(args.output)
    if not template_path.exists():
        print(f"找不到模板文件：{template_path}", file=sys.stderr)
        return 1
    try:
        proxies: list[dict[str, Any]] = []
        subscription_counts: list[tuple[str, int]] = []
        for index, subscription in enumerate(args.subscriptions, start=1):
            source = display_subscription_source(subscription)
            print(f"正在获取订阅 {index}/{len(args.subscriptions)}：{source}")
            raw, _headers = fetch_url(subscription, user_agent=args.user_agent)
            subscription_proxies = parse_subscription(decode_text(raw))
            if not subscription_proxies:
                print(f"警告：该订阅未发现支持的代理节点：{subscription}", file=sys.stderr)
            print(f"  发现节点：{len(subscription_proxies)}")
            subscription_counts.append((source, len(subscription_proxies)))
            proxies.extend(subscription_proxies)
        proxies_before_merge = len(proxies)
        proxies = clean_proxies(proxies)
        if not proxies:
            raise RuntimeError("所有订阅中都没有发现支持的代理节点")
        config = build_config(template_path, proxies, keep_include_all=args.keep_include_all)
        write_yaml(config, output_path)
        if args.update_rules:
            download_rules(config, output_path, user_agent=args.user_agent)
    except Exception as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1

    print_generation_summary(output_path, args.subscriptions, subscription_counts, proxies_before_merge, proxies)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

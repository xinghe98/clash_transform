package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"gopkg.in/yaml.v3"
)

const (
	defaultTemplate = "example.cofig.yaml"
	defaultOutput   = "config.yaml"
	defaultUA       = "clash.meta"
	ruleBase        = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta"
)

var infoNodeRe = regexp.MustCompile(`(?i)traffic|流量|套餐|到期|剩余|订阅|官网|expire|剩余流量|过期`)

var proxyTypeAliases = map[string]string{
	"macc": "ssr",
}

var geoipProviderFiles = map[string]string{
	"private-ip":    "private.mrs",
	"cn-ip":         "cn.mrs",
	"google-ip":     "google.mrs",
	"telegram-ip":   "telegram.mrs",
	"twitter-ip":    "twitter.mrs",
	"facebook-ip":   "facebook.mrs",
	"netflix-ip":    "netflix.mrs",
	"cloudflare-ip": "cloudflare.mrs",
}

type regionDef struct {
	name string
	re   *regexp.Regexp
}

var regionDefinitions = []regionDef{
	{"🇭🇰 香港", regexp.MustCompile(`(?i)香港|港([^口]|$)|hk|hkg|hong\s*kong|hongkong`)},
	{"🇲🇴 澳门", regexp.MustCompile(`(?i)澳门|澳門|mo|macau|macao`)},
	{"🇹🇼 台湾", regexp.MustCompile(`(?i)台湾|台灣|台|tw|twn|taiwan`)},
	{"🇯🇵 日本", regexp.MustCompile(`(?i)日本|日([^志]|$)|jp|jpn|japan|tokyo|osaka`)},
	{"🇸🇬 新加坡", regexp.MustCompile(`(?i)新加坡|坡|狮城|獅城|sg|sgp|singapore`)},
	{"🇺🇸 美国", regexp.MustCompile(`(?i)美国|美國|美|us|usa|united\s*states|america|los\s*angeles|la|san\s*jose|sjc|new\s*york|nyc`)},
	{"🇰🇷 韩国", regexp.MustCompile(`(?i)韩国|韓國|韩|韓|kr|kor|korea|seoul`)},
	{"🇬🇧 英国", regexp.MustCompile(`(?i)英国|英國|英|uk|gb|gbr|united\s*kingdom|britain|london`)},
	{"🇩🇪 德国", regexp.MustCompile(`(?i)德国|德國|德|de|deu|ger|germany|frankfurt`)},
	{"🇫🇷 法国", regexp.MustCompile(`(?i)法国|法國|法|fr|fra|france|paris`)},
	{"🇳🇱 荷兰", regexp.MustCompile(`(?i)荷兰|荷蘭|荷|nl|nld|netherlands|holland|amsterdam`)},
	{"🇨🇦 加拿大", regexp.MustCompile(`(?i)加拿大|加|ca|can|canada|toronto|vancouver`)},
	{"🇦🇺 澳大利亚", regexp.MustCompile(`(?i)澳大利亚|澳大利亞|澳洲|澳|au|aus|australia|sydney|melbourne`)},
	{"🇲🇾 马来西亚", regexp.MustCompile(`(?i)马来西亚|馬來西亞|大马|大馬|马来|馬來|my|mys|malaysia|kuala\s*lumpur|kl`)},
	{"🇹🇭 泰国", regexp.MustCompile(`(?i)泰国|泰國|泰|th|tha|thailand|bangkok`)},
	{"🇵🇭 菲律宾", regexp.MustCompile(`(?i)菲律宾|菲律賓|菲|ph|phl|philippines|manila`)},
	{"🇮🇩 印度尼西亚", regexp.MustCompile(`(?i)印度尼西亚|印尼|id|idn|indonesia|jakarta`)},
	{"🇮🇳 印度", regexp.MustCompile(`(?i)印度|in|ind|india|mumbai|delhi`)},
	{"🇻🇳 越南", regexp.MustCompile(`(?i)越南|越|vn|vnm|vietnam`)},
	{"🇹🇷 土耳其", regexp.MustCompile(`(?i)土耳其|土|tr|tur|turkey|istanbul`)},
	{"🇦🇷 阿根廷", regexp.MustCompile(`(?i)阿根廷|阿根廷|ar|arg|argentina`)},
	{"🇧🇷 巴西", regexp.MustCompile(`(?i)巴西|br|bra|brazil|sao\s*paulo`)},
	{"🇲🇽 墨西哥", regexp.MustCompile(`(?i)墨西哥|mx|mex|mexico`)},
	{"🇷🇺 俄罗斯", regexp.MustCompile(`(?i)俄罗斯|俄羅斯|俄|ru|rus|russia|moscow`)},
	{"🇺🇦 乌克兰", regexp.MustCompile(`(?i)乌克兰|烏克蘭|ua|ukr|ukraine`)},
}

const otherRegionGroup = "🌍 其他地区"

func fetchURL(target string, timeout int, ua string) ([]byte, http.Header, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, nil, fmt.Errorf("下载失败：%w", err)
	}
	if parsed.Scheme == "file" {
		data, err := os.ReadFile(parsed.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("下载失败：%w", err)
		}
		return data, http.Header{}, nil
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("下载失败：%w", err)
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("下载失败：%w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("下载失败：%w", err)
	}
	headers := make(map[string][]string)
	for k, v := range resp.Header {
		headers[strings.ToLower(k)] = v
	}
	return body, headers, nil
}

func decodeText(data []byte) string {
	for _, enc := range []string{"utf-8", "utf-8-sig"} {
		if enc == "utf-8" {
			if s, err := decodeUTF8(data); err == nil {
				return s
			}
		} else {
			// utf-8-sig handled by stripping BOM then utf-8
			if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
				if s, err := decodeUTF8(data[3:]); err == nil {
					return s
				}
			}
		}
	}
	// GB18030 / GBK / GB2312 via simplifiedchinese
	decoder := simplifiedchinese.GB18030.NewDecoder()
	out, err := io.ReadAll(transform.NewReader(bytes.NewReader(data), decoder))
	if err == nil {
		return string(out)
	}
	return decodeLossy(data)
}

func decodeUTF8(data []byte) (string, error) {
	if !utf8Valid(data) {
		return "", fmt.Errorf("invalid utf-8")
	}
	return string(data), nil
}

func utf8Valid(data []byte) bool {
	return !strings.ContainsRune(string(data), '�') && utf8Check(data)
}

// fast path: strings.ToValidUTF8-like check using utf8.DecodeRune
func utf8Check(data []byte) bool {
	for len(data) > 0 {
		r, size := decodeRune(data)
		if r == 0xFFFD && size == 1 {
			return false
		}
		data = data[size:]
	}
	return true
}

// simplified decoder for validity checks
func decodeRune(b []byte) (rune, int) {
	if len(b) == 0 {
		return 0xFFFD, 1
	}
	b0 := b[0]
	x := uint32(b0)
	switch {
	case x < 0x80:
		return rune(b0), 1
	case x < 0xC2:
		return 0xFFFD, 1
	case x < 0xE0:
		if len(b) < 2 {
			return 0xFFFD, 1
		}
		b1 := b[1]
		if b1&0xC0 != 0x80 || x == 0xC0 || x == 0xC1 {
			return 0xFFFD, 1
		}
		return rune(x&0x1F)<<6 | rune(b1&0x3F), 2
	case x < 0xF0:
		if len(b) < 3 {
			return 0xFFFD, 1
		}
		b1, b2 := b[1], b[2]
		if b1&0xC0 != 0x80 || b2&0xC0 != 0x80 {
			return 0xFFFD, 1
		}
		r := rune(x&0x0F)<<12 | rune(b1&0x3F)<<6 | rune(b2&0x3F)
		if r < 0x0800 {
			return 0xFFFD, 1
		}
		return r, 3
	case x < 0xF5:
		if len(b) < 4 {
			return 0xFFFD, 1
		}
		b1, b2, b3 := b[1], b[2], b[3]
		if b1&0xC0 != 0x80 || b2&0xC0 != 0x80 || b3&0xC0 != 0x80 {
			return 0xFFFD, 1
		}
		r := rune(x&0x07)<<18 | rune(b1&0x3F)<<12 | rune(b2&0x3F)<<6 | rune(b3&0x3F)
		if r < 0x10000 || r >= 0x110000 {
			return 0xFFFD, 1
		}
		return r, 4
	default:
		return 0xFFFD, 1
	}
}

func decodeLossy(data []byte) string {
	var buf strings.Builder
	for len(data) > 0 {
		r, size := decodeRune(data)
		if r == 0xFFFD && size == 1 {
			buf.WriteRune('�')
		} else {
			buf.WriteRune(r)
		}
		data = data[size:]
	}
	return buf.String()
}

func b64decodeText(value string) (string, error) {
	compact := strings.Join(strings.Fields(value), "")
	compact = strings.ReplaceAll(compact, "-", "+")
	compact = strings.ReplaceAll(compact, "_", "/")
	padding := strings.Repeat("=", (4-len(compact)%4)%4)
	data, err := base64.StdEncoding.DecodeString(compact + padding)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func maybeBase64Subscription(text string) string {
	stripped := strings.TrimSpace(text)
	if stripped == "" {
		return stripped
	}
	if regexp.MustCompile(`(?m)^\s*(proxies|proxy-providers|proxy-groups|rules)\s*:`).MatchString(stripped) {
		return stripped
	}
	if regexp.MustCompile(`(?m)^\s*(ss|ssr|vmess|vless|trojan|hysteria2|hy2)://`).MatchString(stripped) {
		return stripped
	}
	decoded, err := b64decodeText(stripped)
	if err != nil {
		return stripped
	}
	if regexp.MustCompile(`(?m)^\s*(ss|ssr|vmess|vless|trojan|hysteria2|hy2)://`).MatchString(decoded) {
		return decoded
	}
	return stripped
}

func parseYAMLConfig(text string) (map[string]any, bool) {
	var loaded any
	if err := yaml.Unmarshal([]byte(text), &loaded); err != nil {
		return nil, false
	}
	m, ok := loaded.(map[string]any)
	if !ok {
		return nil, false
	}
	proxies, ok := m["proxies"].([]any)
	if !ok || len(proxies) == 0 {
		return nil, false
	}
	return m, true
}

func parsePluginOpts(query url.Values) (string, map[string]any) {
	pluginValues := query["plugin"]
	if len(pluginValues) == 0 {
		return "", nil
	}
	decoded, _ := url.QueryUnescape(pluginValues[0])
	parts := strings.Split(decoded, ";")
	if len(parts) == 0 {
		return "", nil
	}
	plugin := parts[0]
	opts := make(map[string]any)
	for _, part := range parts[1:] {
		if part == "" {
			continue
		}
		if idx := strings.Index(part, "="); idx >= 0 {
			opts[part[:idx]] = part[idx+1:]
		} else {
			opts[part] = true
		}
	}
	if len(opts) == 0 {
		return plugin, nil
	}
	return plugin, opts
}

func parseSS(link string) (map[string]any, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	name := "ss"
	if parsed.Fragment != "" {
		name, _ = url.QueryUnescape(parsed.Fragment)
	}
	query := parsed.Query()

	userinfo := parsed.User.Username()
	server := parsed.Hostname()
	portStr := parsed.Port()
	var method, password string

	if userinfo != "" && !strings.Contains(userinfo, ":") {
		decoded, err := b64decodeText(userinfo)
		if err != nil {
			return nil, fmt.Errorf("无效的 ss 用户信息")
		}
		colon := strings.Index(decoded, ":")
		if colon < 0 {
			return nil, fmt.Errorf("无效的 ss 用户信息")
		}
		method = decoded[:colon]
		password = decoded[colon+1:]
	} else if userinfo != "" {
		method, _ = url.QueryUnescape(userinfo)
		pass, _ := parsed.User.Password()
		password, _ = url.QueryUnescape(pass)
	} else {
		raw := link[len("ss://"):]
		if i := strings.Index(raw, "#"); i >= 0 {
			raw = raw[:i]
		}
		if i := strings.Index(raw, "?"); i >= 0 {
			raw = raw[:i]
		}
		decoded, err := b64decodeText(raw)
		if err != nil {
			return nil, fmt.Errorf("无效的 ss 用户信息")
		}
		at := strings.LastIndex(decoded, "@")
		if at < 0 {
			return nil, fmt.Errorf("无效的 ss 用户信息")
		}
		methodPassword := decoded[:at]
		address := decoded[at+1:]
		colon := strings.LastIndex(methodPassword, ":")
		if colon < 0 {
			return nil, fmt.Errorf("无效的 ss 用户信息")
		}
		method = methodPassword[:colon]
		password = methodPassword[colon+1:]
		portIdx := strings.LastIndex(address, ":")
		if portIdx < 0 {
			return nil, fmt.Errorf("无效的 ss 服务器或端口")
		}
		server = address[:portIdx]
		portStr = address[portIdx+1:]
	}

	if server == "" || portStr == "" {
		return nil, fmt.Errorf("无效的 ss 服务器或端口")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("无效的 ss 服务器或端口")
	}

	proxy := map[string]any{
		"name":     name,
		"type":     "ss",
		"server":   server,
		"port":     port,
		"cipher":   method,
		"password": password,
		"udp":      true,
	}
	plugin, pluginOpts := parsePluginOpts(query)
	if plugin != "" {
		proxy["plugin"] = plugin
	}
	if pluginOpts != nil {
		proxy["plugin-opts"] = pluginOpts
	}
	return proxy, nil
}

func parseVmess(link string) (map[string]any, error) {
	payload, err := b64decodeText(link[len("vmess://"):])
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return nil, err
	}
	name := firstOf(data["ps"], data["name"], "vmess")
	proxy := map[string]any{
		"name":    name,
		"type":    "vmess",
		"server":  data["add"],
		"port":    toInt(data["port"]),
		"uuid":    data["id"],
		"alterId": toInt(orZero(data["aid"])),
		"cipher":  firstOf(data["scy"], data["cipher"], "auto"),
		"udp":     true,
	}
	network := anyString(data["net"])
	if network != "" {
		proxy["network"] = network
	}
	tls := anyString(data["tls"])
	if tls != "" {
		proxy["tls"] = tls == "tls" || tls == "true"
	}
	servername := firstOf(data["sni"], data["host"])
	if servername != "" && proxy["tls"] == true {
		proxy["servername"] = servername
	}
	if network == "ws" {
		headers := map[string]any{}
		if host := anyString(data["host"]); host != "" {
			headers["Host"] = host
		}
		proxy["ws-opts"] = map[string]any{
			"path":    orSlash(data["path"]),
			"headers": headers,
		}
	}
	return proxy, nil
}

func parseTrojanOrVless(link string, kind string) (map[string]any, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	name := kind
	if parsed.Fragment != "" {
		name, _ = url.QueryUnescape(parsed.Fragment)
	}
	if parsed.Hostname() == "" || parsed.Port() == "" || parsed.User == nil {
		return nil, fmt.Errorf("无效的 %s 链接", kind)
	}
	port, _ := strconv.Atoi(parsed.Port())
	proxy := map[string]any{
		"name":   name,
		"type":   kind,
		"server": parsed.Hostname(),
		"port":   port,
		"udp":    true,
	}
	if kind == "trojan" {
		proxy["password"], _ = url.QueryUnescape(parsed.User.Username())
	} else {
		proxy["uuid"], _ = url.QueryUnescape(parsed.User.Username())
		if flow := query.Get("flow"); flow != "" {
			proxy["flow"] = flow
		}
	}
	security := orFirst(query.Get("security"), query.Get("tls"))
	if security == "tls" || security == "reality" {
		proxy["tls"] = true
	}
	if security == "reality" {
		realityOpts := map[string]any{}
		if pbk := query.Get("pbk"); pbk != "" {
			realityOpts["public-key"] = pbk
		}
		if sid := query.Get("sid"); sid != "" {
			realityOpts["short-id"] = sid
		}
		proxy["reality-opts"] = realityOpts
	}
	sni := orFirst(query.Get("sni"), query.Get("peer"))
	if sni != "" {
		proxy["servername"] = sni
	}
	network := orFirst(query.Get("type"), query.Get("network"))
	if network != "" {
		proxy["network"] = network
	}
	if network == "ws" {
		host := query.Get("host")
		headers := map[string]any{}
		if host != "" {
			headers["Host"] = host
		}
		proxy["ws-opts"] = map[string]any{
			"path":    orSlash(query.Get("path")),
			"headers": headers,
		}
	}
	return proxy, nil
}

func parseHysteria2(link string) (map[string]any, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	if parsed.Hostname() == "" || parsed.Port() == "" {
		return nil, fmt.Errorf("无效的 hysteria2 链接")
	}
	port, _ := strconv.Atoi(parsed.Port())
	name := "hysteria2"
	if parsed.Fragment != "" {
		name, _ = url.QueryUnescape(parsed.Fragment)
	}
	password := ""
	if parsed.User != nil {
		password, _ = url.QueryUnescape(parsed.User.Username())
	}
	if password == "" {
		password = query.Get("password")
	}
	proxy := map[string]any{
		"name":     name,
		"type":     "hysteria2",
		"server":   parsed.Hostname(),
		"port":     port,
		"password": password,
	}
	if sni := query.Get("sni"); sni != "" {
		proxy["sni"] = sni
	}
	if insecure := query.Get("insecure"); insecure == "1" || insecure == "true" {
		proxy["skip-cert-verify"] = true
	}
	return proxy, nil
}

func parseLink(line string) map[string]any {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	var proxy map[string]any
	var err error
	switch {
	case strings.HasPrefix(line, "ss://"):
		proxy, err = parseSS(line)
	case strings.HasPrefix(line, "vmess://"):
		proxy, err = parseVmess(line)
	case strings.HasPrefix(line, "trojan://"):
		proxy, err = parseTrojanOrVless(line, "trojan")
	case strings.HasPrefix(line, "vless://"):
		proxy, err = parseTrojanOrVless(line, "vless")
	case strings.HasPrefix(line, "hysteria2://"), strings.HasPrefix(line, "hy2://"):
		proxy, err = parseHysteria2(line)
	}
	if err != nil {
		prefix := line
		if len(prefix) > 48 {
			prefix = prefix[:48] + "..."
		}
		fmt.Fprintf(os.Stderr, "跳过不支持或损坏的节点：%s...（%v）\n", prefix, err)
		return nil
	}
	return proxy
}

func cleanProxies(proxies []any) []map[string]any {
	cleaned := []map[string]any{}
	usedNames := map[string]int{}
	seenKeys := map[[5]any]struct{}{}
	for _, item := range proxies {
		proxy, ok := item.(map[string]any)
		if !ok {
			continue
		}
		proxy = deepCopyMap(proxy)
		name := strings.TrimSpace(anyString(proxy["name"]))
		if name == "" {
			name = "node"
		}
		if infoNodeRe.MatchString(name) {
			continue
		}
		proxyType := strings.ToLower(strings.TrimSpace(anyString(proxy["type"])))
		if normalizedType, ok := proxyTypeAliases[proxyType]; ok {
			proxyType = normalizedType
		}
		if proxyType == "" {
			continue
		}
		proxy["type"] = proxyType
		key := [5]any{proxy["type"], proxy["server"], proxy["port"], proxy["uuid"], proxy["password"]}
		if _, exists := seenKeys[key]; exists {
			continue
		}
		seenKeys[key] = struct{}{}
		count := usedNames[name]
		usedNames[name] = count + 1
		if count == 0 {
			proxy["name"] = name
		} else {
			proxy["name"] = fmt.Sprintf("%s %d", name, count+1)
		}
		cleaned = append(cleaned, proxy)
	}
	return cleaned
}

func deepCopyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopyAny(v)
	}
	return out
}

func deepCopyAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return deepCopyMap(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = deepCopyAny(item)
		}
		return out
	default:
		return x
	}
}

func parseSubscription(text string) []map[string]any {
	normalized := maybeBase64Subscription(text)
	if cfg, ok := parseYAMLConfig(normalized); ok {
		proxies := cfg["proxies"].([]any)
		result := make([]any, len(proxies))
		copy(result, proxies)
		return cleanProxies(result)
	}
	parsed := []any{}
	for _, line := range strings.Split(normalized, "\n") {
		if proxy := parseLink(line); proxy != nil {
			parsed = append(parsed, proxy)
		}
	}
	return cleanProxies(parsed)
}

func ruleURL(providerName string, provider map[string]any) string {
	behavior := anyString(provider["behavior"])
	section := "geo/geosite"
	if behavior == "ipcidr" || strings.HasSuffix(providerName, "-ip") {
		section = "geo/geoip"
	}
	filename := geoipProviderFiles[providerName]
	if filename == "" {
		path := anyString(provider["path"])
		if path != "" {
			filename = filepath.Base(path)
		}
	}
	if filename == "" {
		filename = providerName + ".mrs"
	}
	if !strings.HasSuffix(filename, ".mrs") {
		filename = providerName + ".mrs"
	}
	return fmt.Sprintf("%s/%s/%s", ruleBase, section, filename)
}

func normalizeRuleProviders(config map[string]any) {
	providers, ok := config["rule-providers"].(map[string]any)
	if !ok {
		return
	}
	for name, value := range providers {
		provider, ok := value.(map[string]any)
		if !ok {
			continue
		}
		provider["type"] = "http"
		if _, has := provider["behavior"]; !has {
			provider["behavior"] = "domain"
		}
		provider["url"] = ruleURL(name, provider)
		pathBase := anyString(provider["path"])
		if pathBase == "" {
			pathBase = name + ".mrs"
		}
		provider["path"] = "./ruleset/" + filepath.Base(pathBase)
		provider["interval"] = toInt(provider["interval"])
		if provider["interval"] == 0 {
			provider["interval"] = 86400
		}
		provider["format"] = "mrs"
	}
}

func validateRuleReferences(config map[string]any) error {
	providers := map[string]any{}
	if p, ok := config["rule-providers"].(map[string]any); ok {
		providers = p
	}
	rules := []any{}
	if r, ok := config["rules"].([]any); ok {
		rules = r
	}
	missing := map[string]struct{}{}
	for _, item := range rules {
		rule, ok := item.(string)
		if !ok {
			continue
		}
		parts := strings.Split(rule, ",")
		if len(parts) >= 2 {
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			if parts[0] == "RULE-SET" {
				if _, exists := providers[parts[1]]; !exists {
					missing[parts[1]] = struct{}{}
				}
			}
		}
	}
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for k := range missing {
			names = append(names, k)
		}
		sort.Strings(names)
		return fmt.Errorf("规则引用了不存在的 rule-providers：%s", strings.Join(names, ", "))
	}
	return nil
}

func groupHasIncludeAll(group map[string]any) bool {
	v, ok := group["include-all"]
	if !ok {
		return false
	}
	return toBool(v)
}

func explicitProxyGroups(config map[string]any, proxies []map[string]any) {
	groupsAny, ok := config["proxy-groups"].([]any)
	if !ok {
		return
	}
	nodeNames := make([]string, len(proxies))
	for i, p := range proxies {
		nodeNames[i] = anyString(p["name"])
	}
	regionalMatches, otherNodes := detectRegionNodes(nodeNames)
	regionGroupNames := make([]string, 0, len(regionalMatches))
	for _, def := range regionDefinitions {
		if _, ok := regionalMatches[def.name]; ok {
			regionGroupNames = append(regionGroupNames, def.name)
		}
	}
	if len(otherNodes) > 0 {
		regionGroupNames = append(regionGroupNames, otherRegionGroup)
	}
	oldRegionNames := map[string]struct{}{otherRegionGroup: {}}
	for _, def := range regionDefinitions {
		oldRegionNames[def.name] = struct{}{}
	}

	groups := make([]map[string]any, 0, len(groupsAny))
	for _, g := range groupsAny {
		if group, ok := g.(map[string]any); ok {
			groups = append(groups, group)
		} else {
			// Preserve non-dict entries? Maintain list of any contains nil? Python keeps dicts; here we'll skip unknown.
		}
	}

	firstRegionIndex := len(groups)
	for i, group := range groups {
		name := anyString(group["name"])
		if _, exists := oldRegionNames[name]; exists {
			firstRegionIndex = i
			break
		}
	}
	insertAt := 0
	for _, group := range groups[:firstRegionIndex] {
		name := anyString(group["name"])
		if _, exists := oldRegionNames[name]; !exists {
			insertAt++
		}
	}

	nonRegionGroups := make([]map[string]any, 0, len(groups))
	for _, group := range groups {
		name := anyString(group["name"])
		if _, exists := oldRegionNames[name]; !exists {
			nonRegionGroups = append(nonRegionGroups, group)
		}
	}

	for _, group := range nonRegionGroups {
		name := anyString(group["name"])
		_ = name
		currentAny := group["proxies"]
		current := []any{}
		if c, ok := currentAny.([]any); ok {
			current = c
		}
		if groupHasIncludeAll(group) {
			delete(group, "include-all")
			delete(group, "filter")
			delete(group, "exclude-filter")
			group["proxies"] = dedupeAny(append(
				replaceRegionRefs(current, regionGroupNames, oldRegionNames),
				toAnyStrings(nodeNames)...,
			))
		} else if len(current) > 0 {
			group["proxies"] = replaceRegionRefs(current, regionGroupNames, oldRegionNames)
		}
	}

	dynamicRegionGroups := make([]map[string]any, 0)
	for _, name := range regionGroupNames {
		nodes := regionalMatches[name]
		if nodes == nil {
			nodes = otherNodes
		}
		dynamicRegionGroups = append(dynamicRegionGroups, map[string]any{
			"name":    name,
			"type":    "select",
			"proxies": toAnyStrings(nodes),
		})
	}

	result := make([]any, 0, len(nonRegionGroups)+len(dynamicRegionGroups))
	result = append(result, toAnyMaps(nonRegionGroups[:insertAt])...)
	result = append(result, toAnyMaps(dynamicRegionGroups)...)
	result = append(result, toAnyMaps(nonRegionGroups[insertAt:])...)
	config["proxy-groups"] = result
}

func detectRegionNodes(nodeNames []string) (map[string][]string, []string) {
	matches := map[string][]string{}
	matched := map[string]struct{}{}
	for _, def := range regionDefinitions {
		nodes := []string{}
		for _, name := range nodeNames {
			if _, ok := matched[name]; ok {
				continue
			}
			if def.re.MatchString(name) {
				nodes = append(nodes, name)
				matched[name] = struct{}{}
			}
		}
		if len(nodes) > 0 {
			matches[def.name] = nodes
		}
	}
	other := []string{}
	for _, name := range nodeNames {
		if _, ok := matched[name]; ok {
			continue
		}
		if !infoNodeRe.MatchString(name) {
			other = append(other, name)
		}
	}
	return matches, other
}

func replaceRegionRefs(items []any, regionGroupNames []string, oldRegionNames map[string]struct{}) []any {
	result := []any{}
	inserted := false
	for _, item := range items {
		if s, ok := item.(string); ok {
			if _, exists := oldRegionNames[s]; exists {
				if !inserted {
					for _, name := range regionGroupNames {
						result = append(result, name)
					}
					inserted = true
				}
				continue
			}
		}
		result = append(result, item)
	}
	return dedupeAny(result)
}

func dedupeAny(items []any) []any {
	result := []any{}
	seen := map[string]struct{}{}
	for _, item := range items {
		key := fmt.Sprintf("%v", item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, item)
	}
	return result
}

func displaySubscriptionSource(u string) string {
	parsed, err := url.Parse(u)
	if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
		tail := filepath.Base(parsed.Path)
		if tail != "" {
			if len(tail) > 10 {
				tail = "..." + tail[len(tail)-6:]
			}
			return parsed.Host + "/" + tail
		}
		return parsed.Host
	}
	if parsed.Scheme == "file" {
		return "file://" + filepath.Base(parsed.Path)
	}
	if len(u) <= 80 {
		return u
	}
	return u[:32] + "..." + u[len(u)-16:]
}

func printGenerationSummary(
	outputPath string,
	subscriptions []string,
	subscriptionCounts []struct {
		source string
		count  int
	},
	proxiesBeforeMerge int,
	proxies []map[string]any,
) {
	nodeNames := make([]string, len(proxies))
	for i, p := range proxies {
		nodeNames[i] = anyString(p["name"])
	}
	regionalMatches, otherNodes := detectRegionNodes(nodeNames)
	regionNames := make([]string, 0, len(regionalMatches))
	for _, def := range regionDefinitions {
		if _, ok := regionalMatches[def.name]; ok {
			regionNames = append(regionNames, def.name)
		}
	}
	if len(otherNodes) > 0 {
		regionNames = append(regionNames, otherRegionGroup)
	}
	typeCounts := map[string]int{}
	for _, proxy := range proxies {
		t := anyString(proxy["type"])
		if t == "" {
			t = "unknown"
		}
		typeCounts[t]++
	}
	typePairs := make([]string, 0, len(typeCounts))
	for name := range typeCounts {
		typePairs = append(typePairs, name)
	}
	sort.Strings(typePairs)
	for i, name := range typePairs {
		typePairs[i] = fmt.Sprintf("%s=%d", name, typeCounts[name])
	}

	fmt.Println("\n转换摘要")
	fmt.Printf("  输出文件：%s\n", outputPath)
	fmt.Printf("  订阅数量：%d\n", len(subscriptions))
	for i, sc := range subscriptionCounts {
		fmt.Printf("    %d. %s：%d 个节点\n", i+1, sc.source, sc.count)
	}
	fmt.Printf("  合并前节点数：%d\n", proxiesBeforeMerge)
	fmt.Printf("  去重后节点数：%d\n", len(proxies))
	fmt.Printf("  去除重复节点：%d\n", max(proxiesBeforeMerge-len(proxies), 0))
	fmt.Printf("  国家/地区数量：%d\n", len(regionNames))
	if len(regionNames) > 0 {
		fmt.Printf("    %s\n", strings.Join(regionNames, ", "))
	}
	fmt.Printf("  协议类型：%s\n", strings.Join(typePairs, ", "))
	fmt.Println("  规则处理：已规范化 rule-providers 链接；除非使用 --update-rules，否则不会下载本地规则文件")
}

func buildConfig(templatePath string, proxies []map[string]any, keepIncludeAll bool) (map[string]any, error) {
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("读取模板失败：%w", err)
	}
	var config map[string]any
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("模板不是有效的 YAML 映射：%s", templatePath)
	}
	if config == nil {
		return nil, fmt.Errorf("模板不是有效的 YAML 映射：%s", templatePath)
	}
	delete(config, "global-client-fingerprint")
	config["proxies"] = proxies
	normalizeRuleProviders(config)
	if err := validateRuleReferences(config); err != nil {
		return nil, err
	}
	if !keepIncludeAll {
		explicitProxyGroups(config, proxies)
	}
	return config, nil
}

func downloadRules(config map[string]any, outputPath string, ua string) error {
	providers, ok := config["rule-providers"].(map[string]any)
	if !ok {
		return nil
	}
	baseDir := filepath.Dir(outputPath)
	for name, value := range providers {
		provider, ok := value.(map[string]any)
		if !ok {
			continue
		}
		urlStr := anyString(provider["url"])
		pathStr := anyString(provider["path"])
		if urlStr == "" || pathStr == "" {
			continue
		}
		target := filepath.Join(baseDir, strings.TrimPrefix(pathStr, "./"))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("创建规则目录失败：%w", err)
		}
		data, _, err := fetchURL(urlStr, 30, ua)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return fmt.Errorf("写入规则文件失败：%w", err)
		}
		fmt.Printf("已下载规则：%s -> %s\n", name, target)
	}
	return nil
}

type orderedMap struct {
	keys []string
	m    map[string]any
}

func (o orderedMap) MarshalYAML() (any, error) {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, k := range o.keys {
		v, ok := o.m[k]
		if !ok {
			continue
		}
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}
		valNode, err := marshalToNode(v)
		if err != nil {
			return nil, err
		}
		node.Content = append(node.Content, keyNode, valNode)
	}
	return node, nil
}

func marshalToNode(v any) (*yaml.Node, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	if len(node.Content) == 0 {
		return nil, fmt.Errorf("empty yaml node")
	}
	return node.Content[0], nil
}

func mapToOrderedWithPriority(m map[string]any, priority []string) orderedMap {
	seen := map[string]bool{}
	keys := make([]string, 0, len(m))
	for _, k := range priority {
		if _, ok := m[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	extra := make([]string, 0, len(m))
	for k := range m {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	keys = append(keys, extra...)
	return orderedMap{keys: keys, m: m}
}

func proxyToOrdered(p map[string]any) orderedMap {
	priority := []string{
		"name", "type", "server", "port", "uuid", "alterId", "cipher", "password",
		"flow", "udp", "plugin", "plugin-opts", "network", "tls", "sni", "servername",
		"ws-opts", "reality-opts", "skip-cert-verify",
	}
	return mapToOrderedWithPriority(p, priority)
}

func groupsToOrdered(groups []any) []any {
	priority := []string{"name", "type", "proxies", "url", "interval", "behavior", "path", "format", "include-all", "filter", "exclude-filter"}
	out := make([]any, len(groups))
	for i, g := range groups {
		if m, ok := g.(map[string]any); ok {
			out[i] = mapToOrderedWithPriority(m, priority)
		} else {
			out[i] = g
		}
	}
	return out
}

func providersToOrdered(providers map[string]any) orderedMap {
	keys := make([]string, 0, len(providers))
	for k := range providers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return orderedMap{keys: keys, m: providers}
}

func scalarNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

func writeYAML(config map[string]any, templatePath string, outputPath string) error {
	tplBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(tplBytes, &root); err != nil {
		return err
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		data, err := yaml.Marshal(config)
		if err != nil {
			return err
		}
		return os.WriteFile(outputPath, data, 0o644)
	}
	mapping := root.Content[0]

	proxiesList, _ := config["proxies"].([]map[string]any)
	proxiesSeq := make([]any, len(proxiesList))
	for i, p := range proxiesList {
		proxiesSeq[i] = proxyToOrdered(p)
	}
	proxiesNode, err := marshalToNode(proxiesSeq)
	if err != nil {
		return err
	}

	var groupsNode *yaml.Node
	if groups, ok := config["proxy-groups"].([]any); ok {
		groupsNode, err = marshalToNode(groupsToOrdered(groups))
		if err != nil {
			return err
		}
	}

	var rpNode *yaml.Node
	if providers, ok := config["rule-providers"].(map[string]any); ok {
		rpNode, err = marshalToNode(providersToOrdered(providers))
		if err != nil {
			return err
		}
	}

	found := map[string]bool{}
	for i := 0; i < len(mapping.Content); i += 2 {
		key := mapping.Content[i].Value
		if _, ok := config[key]; !ok {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			i -= 2
			continue
		}
		switch key {
		case "proxies":
			mapping.Content[i+1] = proxiesNode
		case "proxy-groups":
			if groupsNode != nil {
				mapping.Content[i+1] = groupsNode
			}
		case "rule-providers":
			if rpNode != nil {
				mapping.Content[i+1] = rpNode
			}
		}
		found[key] = true
	}
	if !found["proxies"] {
		mapping.Content = append(mapping.Content, scalarNode("proxies"), proxiesNode)
	}
	if groupsNode != nil && !found["proxy-groups"] {
		mapping.Content = append(mapping.Content, scalarNode("proxy-groups"), groupsNode)
	}
	if rpNode != nil && !found["rule-providers"] {
		mapping.Content = append(mapping.Content, scalarNode("rule-providers"), rpNode)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(mapping); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return os.WriteFile(outputPath, []byte(unescapeYAMLUnicode(buf.String())), 0o644)
}

var yamlUnicodeEscapeRe = regexp.MustCompile(`\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})`)

func unescapeYAMLUnicode(s string) string {
	return yamlUnicodeEscapeRe.ReplaceAllStringFunc(s, func(match string) string {
		hex := match[2:]
		code, err := strconv.ParseInt(hex, 16, 32)
		if err != nil {
			return match
		}
		return string(rune(code))
	})
}

func splitArgs(args []string) (subArgs []string, flagArgs []string) {
	valueFlags := map[string]bool{
		"-t": true, "--t": true,
		"-o": true, "--o": true,
		"-user-agent": true, "--user-agent": true,
	}
	boolFlags := map[string]bool{
		"-update-rules": true, "--update-rules": true,
		"-keep-include-all": true, "--keep-include-all": true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			subArgs = append(subArgs, arg)
			continue
		}
		name := arg
		eq := strings.Index(arg, "=")
		if eq >= 0 {
			name = arg[:eq]
		}
		flagArgs = append(flagArgs, arg)
		if valueFlags[name] && eq < 0 && i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
		if !valueFlags[name] && !boolFlags[name] {
			// unknown flag; pass through as-is and allow flag package to error later
		}
	}
	return
}

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "基于 example.cofig.yaml 将订阅链接转换为 Clash/Mihomo/OpenClash YAML 配置\n\n")
		fmt.Fprintf(os.Stderr, "用法：transform.go SUBSCRIPTION... [选项]\n\n")
		fmt.Fprintf(os.Stderr, "选项：\n")
		fs.PrintDefaults()
	}
	template := fs.String("t", defaultTemplate, "模板 YAML 路径")
	output := fs.String("o", defaultOutput, "输出 YAML 路径")
	updateRules := fs.Bool("update-rules", false, "转换时下载 rule-provider 的 .mrs 规则文件到本地 ruleset 目录")
	keepIncludeAll := fs.Bool("keep-include-all", false, "保留 Mihomo 专用的 include-all/filter 分组写法")
	userAgent := fs.String("user-agent", defaultUA, "请求订阅时使用的 User-Agent")

	subArgs, flagArgs := splitArgs(os.Args[1:])
	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}

	if len(subArgs) == 0 {
		fmt.Fprintln(os.Stderr, "错误：至少提供一个订阅链接")
		fs.Usage()
		os.Exit(1)
	}
	subscriptions := subArgs

	if _, err := os.Stat(*template); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "找不到模板文件：%s\n", *template)
		os.Exit(1)
	}

	proxies := []map[string]any{}
	subscriptionCounts := []struct {
		source string
		count  int
	}{}

	for i, sub := range subscriptions {
		source := displaySubscriptionSource(sub)
		fmt.Printf("正在获取订阅 %d/%d：%s\n", i+1, len(subscriptions), source)
		raw, _, err := fetchURL(sub, 30, *userAgent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误：%v\n", err)
			os.Exit(1)
		}
		subscriptionProxies := parseSubscription(decodeText(raw))
		if len(subscriptionProxies) == 0 {
			fmt.Fprintf(os.Stderr, "警告：该订阅未发现支持的代理节点：%s\n", sub)
		}
		fmt.Printf("  发现节点：%d\n", len(subscriptionProxies))
		subscriptionCounts = append(subscriptionCounts, struct {
			source string
			count  int
		}{source, len(subscriptionProxies)})
		proxies = append(proxies, subscriptionProxies...)
	}

	proxiesBeforeMerge := len(proxies)
	proxies = cleanProxies(toAnyMapSlice(proxies))
	if len(proxies) == 0 {
		fmt.Fprintln(os.Stderr, "错误：所有订阅中都没有发现支持的代理节点")
		os.Exit(1)
	}

	config, err := buildConfig(*template, proxies, *keepIncludeAll)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}

	if err := writeYAML(config, *template, *output); err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}

	if *updateRules {
		if err := downloadRules(config, *output, *userAgent); err != nil {
			fmt.Fprintf(os.Stderr, "错误：%v\n", err)
			os.Exit(1)
		}
	}

	printGenerationSummary(*output, subscriptions, subscriptionCounts, proxiesBeforeMerge, proxies)
}

// --- helpers ---

func anyString(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func firstOf(values ...any) any {
	for _, v := range values {
		if v != nil && anyString(v) != "" {
			return v
		}
	}
	return ""
}

func orZero(v any) any {
	if v == nil || anyString(v) == "" {
		return 0
	}
	return v
}

func orSlash(v any) string {
	s := anyString(v)
	if s == "" {
		return "/"
	}
	return s
}

func orFirst(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func toInt(v any) int {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	case bool:
		if x {
			return 1
		}
		return 0
	default:
		n, _ := strconv.Atoi(anyString(v))
		return n
	}
}

func toBool(v any) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1" || x == "yes"
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	default:
		return true
	}
}

func toAnyStrings(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func toAnyMaps(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

func toAnyMapSlice(proxies []map[string]any) []any {
	out := make([]any, len(proxies))
	for i, p := range proxies {
		out[i] = p
	}
	return out
}

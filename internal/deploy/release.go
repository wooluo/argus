package deploy

// release.go: GitHub Release 解析——节点程序来源为「远端下载」时，二进制从哪来。
//
// 私有仓库的 Release 资产没有免鉴权直链，而把平台 GitHub Token 送到远端
// 机器又不可取（节点上跑的是半可信自动化）。折中：server 持 token 调 API
// 换取签名下载地址（实测有效期约 48 分钟、仅限该资产），远端只拿签名地址
// 裸下载——token 不出 server，远端也不需要任何凭据。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/wooluo/argus/internal/tools"
)

// 节点程序来源（SSHConfig.Source）。
const (
	SourceServer = "server" // 平台推送：server 经 SSH 上传本机的 argus-node 二进制
	SourceGitHub = "github" // 远端下载：远端机器直接从 GitHub Release 下载
)

// DefaultReleaseRepo Release 所在仓库（部署表单 release_repo 留空时的默认值；
// fork 部署用环境变量 ARGUS_RELEASE_REPO 或表单覆盖）。
const DefaultReleaseRepo = "wooluo/argus"

// gitHubAPI GitHub API 根地址（测试替换为 httptest）。
var gitHubAPI = "https://api.github.com"

// ReleaseAsset 一个待下载的节点二进制资产。
type ReleaseAsset struct {
	Repo   string
	Tag    string // Release tag（如 v0.1.0）
	Name   string // 资产名（argus-node-linux-amd64）
	Size   int64  // 字节数——远端下载后的字节数校验基准
	SHA256 string // 小写 hex；Release 未提供 digest 时为空（只校验字节数）
	id     int64
}

var (
	repoRe = regexp.MustCompile(`^[\w.-]+/[\w.-]+$`)
	tagRe  = regexp.MustCompile(`^[\w.-]{1,100}$`)
)

// releaseHTTP 出站代理策略与平台其余出站请求一致：ARGUS_OUT_PROXY 优先
// （公网才走），否则沿用环境变量 HTTPS_PROXY。TLS 校验保持默认开启——
// 这些请求携带 GitHub Token。
var releaseHTTP = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{Proxy: func(r *http.Request) (*url.URL, error) {
		if p := tools.OutProxyFor(r.URL.String()); p != "" {
			return url.Parse(p)
		}
		return http.ProxyFromEnvironment(r)
	}},
}

// ResolveRelease 查 Release 并挑出 goArch 对应的 argus-node 资产。tag 留空或
// latest = 最新 Release，否则按 tag 查（不带 v 查不到时补 v 重试——本仓库
// tag 形如 v0.1.0，手输 0.1.0 是高频笔误）。token 为空时只能读公开仓库。
func ResolveRelease(repo, tag, goArch, token string) (ReleaseAsset, error) {
	repo, tag, err := normalizeReleaseRef(repo, tag)
	if err != nil {
		return ReleaseAsset{}, err
	}
	rel, status, body, err := getRelease(repo, tag, token)
	if err != nil {
		return ReleaseAsset{}, err
	}
	if status == http.StatusNotFound && tag != "" && !strings.HasPrefix(tag, "v") {
		if r2, st2, _, err2 := getRelease(repo, "v"+tag, token); err2 == nil && st2 == http.StatusOK {
			rel, status = r2, st2
		}
	}
	if status != http.StatusOK {
		return ReleaseAsset{}, releaseErr(repo, tag, status, body)
	}
	want := fmt.Sprintf("argus-node-linux-%s", goArch)
	for _, a := range rel.Assets {
		if a.Name == want {
			return ReleaseAsset{Repo: repo, Tag: rel.TagName, Name: a.Name, Size: a.Size,
				SHA256: strings.TrimPrefix(a.Digest, "sha256:"), id: a.ID}, nil
		}
	}
	return ReleaseAsset{}, fmt.Errorf("Release %s@%s 不含资产 %s（该架构未发布）", repo, rel.TagName, want)
}

// CheckReleaseRef 部署入口预检：仓库/版本格式不合法直接拒绝，免得 SSH
// 连上远端才报格式错。
func CheckReleaseRef(repo, tag string) error {
	_, _, err := normalizeReleaseRef(repo, tag)
	return err
}

// normalizeReleaseRef 仓库与版本归一（latest → 空）+ 格式校验。
func normalizeReleaseRef(repo, tag string) (string, string, error) {
	repo, err := normalizeRepo(repo)
	if err != nil {
		return "", "", err
	}
	tag = strings.TrimSpace(tag)
	if strings.EqualFold(tag, "latest") {
		tag = ""
	}
	if tag != "" && !tagRe.MatchString(tag) {
		return "", "", fmt.Errorf("Release 版本 %q 格式无法识别", tag)
	}
	return repo, tag, nil
}

// SignedURL 用 token 换该资产的签名下载地址（资产 API 的 302 Location）。
// 地址本身即凭据——有效期内任何人可下载该资产，故只在下载前一刻换取，
// 不写日志、不进报错。
func (a ReleaseAsset) SignedURL(token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/repos/%s/releases/assets/%d", gitHubAPI, a.Repo, a.id), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/octet-stream") // 缺它返回的是资产 JSON 而非 302
	setGitHubAuth(req, token)
	// 不跟随跳转：要的就是 302 的 Location
	c := *releaseHTTP
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("换取下载地址失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	loc := resp.Header.Get("Location")
	if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" {
		return "", releaseErr(a.Repo, a.Tag, resp.StatusCode, body)
	}
	return loc, nil
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		Digest string `json:"digest"`
	} `json:"assets"`
}

// getRelease 拉 Release 元数据；非 200 时不报错，交调用方按状态码定提示。
func getRelease(repo, tag, token string) (*ghRelease, int, []byte, error) {
	path := "/repos/" + repo + "/releases/latest"
	if tag != "" {
		path = "/repos/" + repo + "/releases/tags/" + tag
	}
	req, err := http.NewRequest(http.MethodGet, gitHubAPI+path, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "argus-deploy")
	setGitHubAuth(req, token)
	resp, err := releaseHTTP.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("无法访问 GitHub API: %v（server 需能访问 api.github.com，"+
			"或为其配置出站代理 ARGUS_OUT_PROXY / HTTPS_PROXY）", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, body, nil
	}
	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, resp.StatusCode, body, fmt.Errorf("GitHub API 响应无法解析: %v", err)
	}
	return &rel, resp.StatusCode, body, nil
}

func setGitHubAuth(req *http.Request, token string) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// releaseErr API 非 200 → 可操作的提示（message 取 GitHub 响应体的 message）。
func releaseErr(repo, tag string, status int, body []byte) error {
	var e struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &e)
	msg := tools.Truncate(strings.TrimSpace(e.Message), 160)
	switch status {
	case http.StatusNotFound:
		if tag == "" {
			return fmt.Errorf("仓库 %s 不存在或为私有——私有仓库需在设置页配置 GitHub Token", repo)
		}
		return fmt.Errorf("仓库 %s 不存在/私有，或没有 Release %s", repo, tag)
	case http.StatusUnauthorized:
		return fmt.Errorf("GitHub Token 无效或已过期（设置页 → GitHub Token）: %s", msg)
	case http.StatusForbidden:
		return fmt.Errorf("GitHub API 拒绝访问（Token 无该仓库读权限，或未配 Token 时限流）: %s", msg)
	}
	return fmt.Errorf("GitHub API 返回 %d: %s", status, msg)
}

// normalizeRepo 仓库标识归一：空 → ARGUS_RELEASE_REPO → DefaultReleaseRepo；
// 容忍直接粘贴仓库主页地址。
func normalizeRepo(repo string) (string, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		repo = strings.TrimSpace(os.Getenv("ARGUS_RELEASE_REPO"))
	}
	if repo == "" {
		repo = DefaultReleaseRepo
	}
	for _, p := range []string{"https://github.com/", "http://github.com/", "github.com/"} {
		repo = strings.TrimPrefix(repo, p)
	}
	repo = strings.TrimSuffix(repo, "/")
	if !repoRe.MatchString(repo) {
		return "", fmt.Errorf("仓库 %q 格式无法识别（应为 owner/repo）", repo)
	}
	return repo, nil
}

// ---- 远端下载 ----

// fetchFromGitHub 远端机器直接从 GitHub Release 下载节点程序到 dst，返回
// 字节数（后续安装步骤的字节数验证沿用）。每次尝试现换签名地址；成败以
// 效果为准——字节数 + sha256 对账 Release 元数据，远端输出被幽灵吞掉时
// 不误判成败。校验不过重新下载一次（签名地址过期/网络中断各一次机会）。
//
// run 在远端执行命令并返回合并输出；probe 执行探测命令并返回输出——
// 均由 DeployWithProgress 注入，测试用本地 sh 替身覆盖真实 curl/wget 分支。
func fetchFromGitHub(cfg SSHConfig, goArch, dst string,
	run func(string, time.Duration) (string, error), probe func(string) string, step func(string)) (int64, error) {
	asset, err := ResolveRelease(cfg.ReleaseRepo, cfg.ReleaseTag, goArch, cfg.GitHubToken)
	if err != nil {
		return 0, err
	}
	step(fmt.Sprintf("Release %s@%s → %s（%.1f MB）", asset.Repo, asset.Tag, asset.Name,
		float64(asset.Size)/1e6))
	step("远端下载中（免上传，视远端到 GitHub 的带宽数秒至 3 分钟）…")
	for attempt := 1; ; attempt++ {
		signed, err := asset.SignedURL(cfg.GitHubToken)
		if err != nil {
			return 0, err
		}
		// 与 runStepRaw 同款成败标记（远端 exit 码不可信，内建 echo 的回显稳）
		out, _ := run("( "+githubFetchCmd(signed, dst)+" ) && echo __ARGUS_OK__ || echo __ARGUS_FAIL_$?",
			4*time.Minute)
		out = strings.ReplaceAll(out, signed, "<signed-url>") // 报错不带凭据
		switch {
		case strings.Contains(out, "__ARGUS_NOFETCH__"):
			return 0, fmt.Errorf("远端没有 curl / wget，无法下载——远端装其一后重试，或改用「平台推送」")
		case strings.Contains(out, "__ARGUS_FAIL_"):
			host := ""
			if u, err := url.Parse(signed); err == nil {
				host = u.Host
			}
			return 0, fmt.Errorf("远端下载失败: %s——远端机器需能访问 GitHub（%s），不通时改用「平台推送」",
				tools.Truncate(strings.Join(strings.Fields(out), " "), 300), orDefaultStr(host, "未知主机"))
		}
		ok, note := verifyFetched(probe, dst, asset)
		if ok {
			step("二进制已下载（" + note + "）")
			return asset.Size, nil
		}
		if attempt >= 2 {
			return 0, fmt.Errorf("下载的节点程序校验未通过（%s）——网络中断或 GitHub 返回了异常内容，"+
				"可重试或改用「平台推送」", note)
		}
		step("校验未通过（" + note + "），重新下载一次…")
	}
}

// githubFetchCmd 远端下载命令：curl 优先、wget 兜底（最小化镜像往往只有
// 其一），都没有则打 __ARGUS_NOFETCH__ 标记。
func githubFetchCmd(signedURL, dst string) string {
	d, s := shQuote(dst), shQuote(signedURL)
	return "rm -f " + d + "; " +
		"if command -v curl >/dev/null 2>&1; then " +
		"curl -fsSL --connect-timeout 15 --max-time 180 -o " + d + " " + s + "; " +
		"elif command -v wget >/dev/null 2>&1; then " +
		"wget -q -T 30 -O " + d + " " + s + "; " +
		"else echo __ARGUS_NOFETCH__; false; fi"
}

// verifyFetched 校验远端已下载的文件：字节数必须等于 Release 元数据，有
// digest 时 sha256 也须一致。远端输出被幽灵吞掉（wc/sha256sum 无输出）时
// 无法校验——放行，交给后续安装步骤的字节数验证兜底，note 写明。
func verifyFetched(probe func(string) string, dst string, a ReleaseAsset) (ok bool, note string) {
	f := strings.Fields(probe("wc -c < " + dst + "; sha256sum " + dst))
	if len(f) == 0 {
		return true, "远端输出丢失，未能校验"
	}
	if n, err := strconv.ParseInt(f[0], 10, 64); err != nil || n != a.Size {
		return false, fmt.Sprintf("字节数 %s ≠ Release 记录的 %d", f[0], a.Size)
	}
	switch {
	case a.SHA256 == "":
		return true, "字节数校验通过（Release 未提供 sha256）"
	case len(f) < 2:
		return true, "字节数校验通过（sha256 输出丢失）"
	case f[1] != a.SHA256:
		return false, "sha256 与 Release digest 不符"
	}
	return true, "字节数 + sha256 校验通过"
}

// shQuote 单引号包裹（含单引号则 '\” 拼接）——签名地址含 & = % 等 shell 元字符。
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

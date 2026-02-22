package anytlsuri

import (
	"anytls/proxy/nodeopts"
	"fmt"
	"net/url"
	"strings"
)

type Node struct {
	Server        string
	Password      string
	SNI           string
	EgressIP      string
	EgressRule    string
	AllowInsecure *bool
	CACertPath    string
}

func HasScheme(raw string) bool {
	raw = strings.TrimSpace(raw)
	return strings.HasPrefix(strings.ToLower(raw), "anytls://")
}

func Parse(raw string) (Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Node{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(u.Scheme), "anytls") {
		return Node{}, fmt.Errorf("scheme must be anytls")
	}
	out := Node{
		Server: strings.TrimSpace(u.Host),
	}
	if u.User != nil {
		// URL userinfo is percent-encoded on wire; Username/Password return decoded text.
		// For anytls URI, the whole userinfo is treated as one credential.
		// Some third-party subscriptions may emit unescaped ":" inside userinfo
		// (for example anytls://token:part2@host), which net/url parses as
		// Username + Password. Re-join them to preserve compatibility.
		user := u.User.Username()
		if pass, hasPass := u.User.Password(); hasPass {
			if user == "" {
				out.Password = pass
			} else {
				out.Password = user + ":" + pass
			}
		} else {
			out.Password = user
		}
	}
	q := u.Query()
	out.SNI = strings.TrimSpace(q.Get("sni"))
	out.EgressIP = strings.TrimSpace(q.Get("egress-ip"))
	out.EgressRule = strings.TrimSpace(q.Get("egress-rule"))
	out.CACertPath = strings.TrimSpace(firstQueryValue(q, "ca-cert-path", "ca_cert_path", "ca-cert", "ca_cert"))
	if rawInsecure := firstQueryValue(q, "insecure", "allow-insecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify"); rawInsecure != "" {
		out.AllowInsecure = nodeopts.ParseOptionalBoolLoose(rawInsecure)
	}
	return out, nil
}

func Build(node Node) (string, error) {
	server := strings.TrimSpace(node.Server)
	password := strings.TrimSpace(node.Password)
	if server == "" || password == "" {
		return "", fmt.Errorf("server/password is required")
	}

	u := &url.URL{
		Scheme: "anytls",
		Host:   server,
		User:   url.User(password),
		Path:   "/",
	}
	q := url.Values{}
	if s := strings.TrimSpace(node.SNI); s != "" {
		q.Set("sni", s)
	}
	if s := strings.TrimSpace(node.EgressIP); s != "" {
		q.Set("egress-ip", s)
	}
	if s := strings.TrimSpace(node.EgressRule); s != "" {
		q.Set("egress-rule", s)
	}
	if node.AllowInsecure != nil {
		if *node.AllowInsecure {
			q.Set("insecure", "1")
		} else {
			q.Set("insecure", "0")
		}
	}
	if s := strings.TrimSpace(node.CACertPath); s != "" {
		q.Set("ca-cert-path", s)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func firstQueryValue(q url.Values, keys ...string) string {
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if v := strings.TrimSpace(q.Get(key)); v != "" {
			return v
		}
	}
	return ""
}

package ray2sing

import (
	"fmt"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// convertLegacyShadowsocksURL detects the legacy SS URI format where
// method:password@host:port is entirely base64-encoded, and converts
// it to the SIP002 format that ParseUrl can handle.
//
//	Legacy:  ss://BASE64(method:password@host:port)#tag
//	SIP002:  ss://BASE64(method:password)@host:port#tag
func convertLegacyShadowsocksURL(rawURL string) string {
	// Strip scheme
	rest := strings.TrimPrefix(rawURL, "ss://")

	// Separate fragment (#tag)
	fragment := ""
	if idx := strings.Index(rest, "#"); idx != -1 {
		fragment = rest[idx:] // includes '#'
		rest = rest[:idx]
	}

	// If there is already an '@' outside base64, it's SIP002 — no conversion needed
	if strings.Contains(rest, "@") {
		return rawURL
	}

	// Try base64 decode
	decoded, err := decodeBase64IfNeeded(rest)
	if err != nil || decoded == rest {
		// Not valid base64 or unchanged — return as-is
		return rawURL
	}

	// Expect decoded = "method:password@host:port"
	atIdx := strings.LastIndex(decoded, "@")
	if atIdx == -1 {
		return rawURL
	}

	userInfo := decoded[:atIdx]   // "method:password"
	hostPort := decoded[atIdx+1:] // "host:port"

	return fmt.Sprintf("ss://%s@%s%s", userInfo, hostPort, fragment)
}

func ShadowsocksSingbox(shadowsocksUrl string) (*T.Outbound, error) {
	shadowsocksUrl = convertLegacyShadowsocksURL(shadowsocksUrl)
	u, err := ParseUrl(shadowsocksUrl, 443)
	if err != nil {
		return nil, err
	}

	decoded := u.Params
	
	defaultMethod := u.Username
	pass:=u.Password
	if u.Password == "" {
		pass = u.Username
		defaultMethod = "none"
	}
	

	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  u.Name,
		Options: &T.ShadowsocksOutboundOptions{
			ServerOptions: u.GetServerOption(),
			Method:        defaultMethod,
			Password:      pass,
			Plugin:        decoded["plugin"],
			PluginOptions: decoded["pluginopts"],
		},
	}

	return &result, nil
}

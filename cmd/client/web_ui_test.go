package main

import (
	"bytes"
	"testing"
)

func TestEmbeddedWebUIKeepsWebPasswordWriteOnly(t *testing.T) {
	data, err := webUIFS.ReadFile("webui/index.html")
	if err != nil {
		t.Fatalf("read embedded web UI failed: %v", err)
	}
	for _, required := range [][]byte{
		[]byte(`web_password:""`),
		[]byte(`server:N.server,password:"",sni:`),
		[]byte(`name:N.name,url:"",enabled:`),
		[]byte(`web_password_set`),
		[]byte(`password_set`),
		[]byte(`dataIndex:"url_set"`),
		[]byte(`autoComplete:"new-password"`),
	} {
		if !bytes.Contains(data, required) {
			t.Fatalf("embedded web UI missing write-only password marker %q", required)
		}
	}
	if bytes.Contains(data, []byte(`web_password:Br.config.web_password`)) ||
		bytes.Contains(data, []byte(`web_password:data.config.web_password`)) ||
		bytes.Contains(data, []byte(`password:node.password`)) ||
		bytes.Contains(data, []byte(`url:N.url`)) ||
		bytes.Contains(data, []byte(`url:item.url`)) {
		t.Fatalf("embedded web UI still refills a secret from API data")
	}
}

package secret_test

import (
	"bytes"
	"log"
	"testing"

	secret "github.com/nasa9084/go-secret"
)

type config struct {
	StringData string
	IntData    int
}

func TestEncrypterDecrypter(t *testing.T) {
	cfg := config{"hogehogefugafuga", 1230}
	var buf bytes.Buffer
	if err := secret.NewEncrypter(&buf).Encrypt(cfg, "passphrase"); err != nil {
		t.Error(err)
		return
	}
	var out config
	if err := secret.NewDecrypter(&buf).Decrypt(&out, "passphrase"); err != nil {
		t.Error(err)
		return
	}
	if out.StringData != "hogehogefugafuga" {
		t.Errorf("out.StringData is not valid: %s != hogehogefugafuga", out.StringData)
		return
	}
	if out.IntData != 1230 {
		t.Errorf("out.IntData is not valid: %d != 1230", out.IntData)
		return
	}
}

func TestEncryptDecrypt(t *testing.T) {
	cfg := config{"hogehogefugafuga", 1230}
	s, err := secret.Encrypt(cfg, "passphrase")
	if err != nil {
		t.Error(err)
		return
	}
	var out config
	if err := secret.Decrypt(s, &out, "passphrase"); err != nil {
		t.Error(err)
		return
	}
	if out.StringData != "hogehogefugafuga" {
		t.Errorf("out.StringData is not valid: %s != hogehogefugafuga", out.StringData)
		return
	}
	if out.IntData != 1230 {
		t.Errorf("out.IntData is not valid: %d != 1230", out.IntData)
		return
	}
}

func ExampleEncrypt() {
	// a config including sensitive data
	type Config struct {
		ID       string
		Password string
	}
	cfg := Config{
		ID:       "somethingID",
		Password: "somethingPassword",
	}
	masterPassword := "qwerty"

	var buf bytes.Buffer
	// you can use Encrypter like json.Encoder
	if err := secret.NewEncrypter(&buf).Encrypt(cfg, masterPassword); err != nil {
		log.Fatal(err)
	}
	// now buf contains encrypted data
}

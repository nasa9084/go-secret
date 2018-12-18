package secret_test

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	secret "github.com/nasa9084/go-secret"
)

type config struct {
	StringData string
	IntData    int
}

const (
	stringData    = "something foo bar baz"
	intData       = 1472085098
	correctPass   = "correct_passphrase"
	incorrectPass = "incorrect_passphrase"
)

var cfg = config{
	StringData: stringData,
	IntData:    intData,
}

func timeFunc() time.Time { return time.Date(2018, time.December, 17, 14, 27, 40, 0, time.UTC) }

type constantReader struct{ v byte }

func (r constantReader) Read(p []byte) (int, error) {
	for i := 0; i < len(p); i++ {
		p[i] = r.v
	}
	return len(p), nil
}

var encryptedData []byte

func setup() {
	secret.SetTimeFunc(timeFunc)
	secret.SetRand(constantReader{'a'})

	f, err := os.Open("testdata/encrypted_config.gpg")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	encryptedData = data
}

func TestMain(m *testing.M) {
	setup()
	m.Run()
}

func TestEncrypter(t *testing.T) {
	var buf bytes.Buffer
	if err := secret.NewEncrypter(&buf).Encrypt(cfg, "correct_passphrase"); err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(encryptedData, buf.Bytes()) {
		t.Error("encrypted data mismatched")
		return
	}
}

func TestDecrypter(t *testing.T) {
	var cfg config
	if err := secret.NewDecrypter(bytes.NewReader(encryptedData)).Decrypt(&cfg, correctPass); err != nil {
		t.Error(err)
		return
	}
	if cfg.StringData != stringData {
		t.Errorf("decrypted data is invalid: %s != %s", cfg.StringData, stringData)
		return
	}
	if cfg.IntData != intData {
		t.Errorf("decrypted data is invalid: %d != %d", cfg.IntData, intData)
		return
	}
}

func TestDecrypterIncorrectPassword(t *testing.T) {
	var cfg config
	if err := secret.NewDecrypter(bytes.NewReader(encryptedData)).Decrypt(&cfg, "incorrect_passphrase"); err == nil {
		t.Error("incorrect password error should be occurred, but not")
		return
	}
}

func TestDecrypterNotPointer(t *testing.T) {
	var cfg config
	if err := secret.NewDecrypter(bytes.NewReader(encryptedData)).Decrypt(cfg, correctPass); err == nil {
		t.Error("not pointer error should be occurred, but not")
		return
	}
}

func TestEncrypt(t *testing.T) {
	encrypted, err := secret.Encrypt(cfg, correctPass)
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(encryptedData, encrypted) {
		t.Error("encrypted data mismatched")
		return
	}
}

func TestDecrypt(t *testing.T) {
	var decrypted config
	if err := secret.Decrypt(encryptedData, &decrypted, correctPass); err != nil {
		t.Error(err)
		return
	}
	if decrypted.StringData != stringData {
		t.Errorf("decrypted data is invalid: %s != %s", decrypted.StringData, stringData)
		return
	}
	if decrypted.IntData != intData {
		t.Errorf("decrypted data is invalid: %d != %d", decrypted.IntData, intData)
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

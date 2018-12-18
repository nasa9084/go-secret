go-secret
=========

Symmetrically encrypt and decrypt with passphrase using OpenPGP


## SYNOPSIS

``` go
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

```

package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sync"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// TimeFunc is used for encryption.
// Basically, you should NOT touch this.
// This  variable is just for testing purpose.
// See also Config.Time in https://godoc.org/golang.org/x/crypto/openpgp/packet#Config
var TimeFunc func() time.Time

// Rand is used for encryption.
// Basically, you should NOT touch this.
// This  variable is just for testing purpose.
// See also Config.Rand in https://godoc.org/golang.org/x/crypto/openpgp/packet#Config
var Rand io.Reader

type encryptState struct {
	bytes.Buffer
}

var encryptStatePool sync.Pool

func newEncryptState() *encryptState {
	if v := encryptStatePool.Get(); v != nil {
		e := v.(*encryptState)
		e.Reset()
		return e
	}
	return new(encryptState)
}

func (e *encryptState) encrypt(v interface{}, passphrase string) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return err
	}
	w, err := openpgp.SymmetricallyEncrypt(e, []byte(passphrase), nil, &packet.Config{Rand: Rand, Time: TimeFunc})
	if err != nil {
		return err
	}
	defer w.Close()
	if _, err := io.Copy(w, &buf); err != nil {
		return err
	}
	return nil
}

// Encrypt retruns the encrypted byte array of v.
// Before encrypting, Encrypt serializes v as json
func Encrypt(v interface{}, passphrase string) ([]byte, error) {
	e := newEncryptState()
	defer encryptStatePool.Put(e)
	if err := e.encrypt(v, passphrase); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// An Encrypter writes encrypted values to an output stream.
type Encrypter struct {
	w   io.Writer
	err error
}

// NewEncrypter returns a new encrypter that writes to w.
func NewEncrypter(w io.Writer) *Encrypter {
	return &Encrypter{w: w}
}

// Encrypt writes the encrypted value of v to the stream.
// Before encrypting, Encrypt serializes v as json.
func (enc *Encrypter) Encrypt(v interface{}, passphrase string) error {
	if enc.err != nil {
		return enc.err
	}
	e := newEncryptState()
	defer encryptStatePool.Put(e)
	if err := e.encrypt(v, passphrase); err != nil {
		return err
	}
	if _, err := enc.w.Write(e.Bytes()); err != nil {
		enc.err = err
		return err
	}
	return nil
}

type decryptState struct {
	data io.Reader
}

var decryptStatePool sync.Pool

func newDecryptState() *decryptState {
	if v := decryptStatePool.Get(); v != nil {
		d := v.(*decryptState)
		return d
	}
	return new(decryptState)
}

func onetimePrompt(passphrase string) openpgp.PromptFunction {
	var alreadyCalled bool
	return func([]openpgp.Key, bool) ([]byte, error) {
		if alreadyCalled {
			return nil, errors.New("the passphrase is incorrect")
		}
		alreadyCalled = true
		return []byte(passphrase), nil
	}
}

func (d *decryptState) init(data []byte) {
	d.data = bytes.NewReader(data)
}

func (d *decryptState) initWithReader(data io.Reader) {
	var buf bytes.Buffer
	io.Copy(&buf, data)
	d.data = &buf
}

func (d *decryptState) decrypt(v interface{}, passphrase string) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return errors.New("v must be non-empty pointer type")
	}
	promptFn := onetimePrompt(passphrase)
	md, err := openpgp.ReadMessage(d.data, nil, promptFn, nil)
	if err != nil {
		return err
	}
	if err := json.NewDecoder(md.UnverifiedBody).Decode(v); err != nil {
		return err
	}
	return nil
}

// Decrypt given data as encrypted with passphrase, and stores decrypted result into v.
func Decrypt(data []byte, v interface{}, passphrase string) error {
	d := newDecryptState()
	defer decryptStatePool.Put(d)
	d.init(data)
	if err := d.decrypt(v, passphrase); err != nil {
		return err
	}
	return nil
}

// Decrypter reads and decrypt from an input stream.
type Decrypter struct {
	r   io.Reader
	err error
}

// NewDecrypter returns a new decrypter that reads from r.
func NewDecrypter(r io.Reader) *Decrypter {
	return &Decrypter{r: r}
}

// Decrypt encrypted value with passphrase and stores decrypted result into v.
func (dec *Decrypter) Decrypt(v interface{}, passphrase string) error {
	if dec.err != nil {
		return dec.err
	}
	d := newDecryptState()
	defer decryptStatePool.Put(d)
	d.initWithReader(dec.r)
	if err := d.decrypt(v, passphrase); err != nil {
		return err
	}
	return nil
}

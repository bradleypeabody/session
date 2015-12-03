package session

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type TestSsnData struct {
	TestValue1 string
	TestValue2 string
}

func TestSession(t *testing.T) {

	fmt.Printf("TestSession\n")

	TEST_KEY := make([]byte, 16)
	rand.Read(TEST_KEY)
	// TEST_KEY := []byte{26, 217, 121, 223, 2, 25, 13, 182, 88, 177, 153, 177, 110, 211, 160, 104}

	fmt.Printf("TEST_KEY: %v\n", TEST_KEY)

	cryptor := NewSimpleCryptor(TEST_KEY, "testssn")

	testSsnData := &TestSsnData{TestValue1: "hello1", TestValue2: "hello2abcd"}
	fmt.Printf("testSsnData before encoding: %v\n", testSsnData)

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()

	err = cryptor.Write(testSsnData, w, r)
	if err != nil {
		panic(err)
	}

	fmt.Printf("HEADER: %v\n", w.Header())
	cval := w.Header().Get("Set-Cookie")

	// cvalparts := strings.Split(cval, "=")
	// actualcval := cvalparts[1]

	// now try to decode
	testSsnData = &TestSsnData{}
	r, err = http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Cookie", cval)
	err = cryptor.Read(testSsnData, r)
	if err != nil {
		t.Fatal(err)
	}

	if testSsnData.TestValue1 != "hello1" {
		t.Fatalf("TestValue1 expected %v got %v", "hello1", testSsnData.TestValue1)
	}
	if testSsnData.TestValue2 != "hello2abcd" {
		t.Fatalf("TestValue2 expected %v got %v", "hello2abcd", testSsnData.TestValue2)
	}

	fmt.Printf("testSsnData after decoding: %v\n", testSsnData)

}

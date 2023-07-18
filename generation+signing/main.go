package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os/exec"
	"strings"
	"time"

	"github.com/fullsailor/pkcs7"
)

var (
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	certificate *x509.Certificate
)

func main() {
	// Генерування ключів та сертифікату
	generateKeysAndCertificate()
	printKeysAndCertificate()

	// Зчитування вмісту файлу контракту
	contractData, err := readContractFile("contract.py")
	handleError("Не вдалося прочитати файл смарт контракту:", err)

	// Перевірка контракту перед підписанням
	err = validateContract(contractData)
	handleError("Неприпустимий контракт:", err)

	// Підписання контракту
	signedContract, err := signContract(contractData)
	handleError("Не вдалося підписати смарт контракт:", err)

	// Вивід на екран результату підписання контракту
	fmt.Println("Смарт контракт підписано успішно.")

	// Збереження підписаного контракту у файл
	err = saveSignedContract(signedContract)
	handleError("Не вдалося зберегти підписаний контракт:", err)

	// Виконання пайтоновської програми з підписаного контракту
	result, err := executePythonProgram("contract.py")
	handleError("Помилка при виконанні пайтоновської програми:", err)

	// Вивід на екран результату виконання пайтоновської програми
	fmt.Println("Результат виконання пайтоновської програми:")
	fmt.Println(result)

	fmt.Println("Операції завершено успішно.")
}

// generateKeysAndCertificate генерує приватний ключ, публічний ключ і самопідписаний сертифікат
func generateKeysAndCertificate() {
	// Генерування приватного ключа
	privateKey, _ = generatePrivateKey()
	publicKey = &privateKey.PublicKey
	// Генерування самопідписаного сертифіката
	certificate, _ = generateCertificate(privateKey)
}

// generatePrivateKey генерує приватний ключ RSA
func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048) // Розмір ключа RSA встановлено на 2048 біт
}

// generateCertificate створює самопідписаний сертифікат
func generateCertificate(privateKey *rsa.PrivateKey) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// printKeysAndCertificate виводить на екран публічний ключ, приватний ключ і сертифікат
func printKeysAndCertificate() {
	fmt.Println("Публічний ключ:")
	fmt.Println(formatPublicKey(publicKey))

	fmt.Println("Приватний ключ:")
	fmt.Println(formatPrivateKey(privateKey))

	fmt.Println("Сертифікат:")
	fmt.Println(formatCertificate(certificate))
}

// readContractFile зчитує вміст файлу контракту
func readContractFile(filename string) ([]byte, error) {
	contractData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return contractData, nil
}

// validateContract перевіряє контракт перед підписанням
func validateContract(contract []byte) error {
	contractStr := string(contract)
	lines := strings.Split(contractStr, "\n")

	// Перевірка довжини тіла контракту
	if len(lines) > 30 {
		return errors.New("Тіло контракту перевищує 30 рядків")
	}

	// Перевірка наявності math або numpy
	hasMath := false
	hasNumpy := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.Contains(trimmedLine, "import math") {
			hasMath = true
		} else if strings.Contains(trimmedLine, "import numpy") {
			hasNumpy = true
		} else if strings.Contains(trimmedLine, "open(") || strings.Contains(trimmedLine, "socket.") {
			return errors.New("Контракт не може містити виклики функцій роботи з файлами або мережею")
		}
	}

	if !hasMath && !hasNumpy {
		return errors.New("Контракт повинен містити імпорт бібліотеки math або numpy")
	}

	return nil
}

// signContract підписує контракт за допомогою приватного ключа
func signContract(contract []byte) ([]byte, error) {
	p7, err := pkcs7.NewSignedData(contract)
	if err != nil {
		return nil, err
	}

	if err := p7.AddSigner(certificate, privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}

	signedData, err := p7.Finish()
	if err != nil {
		return nil, err
	}

	return signedData, nil
}

// saveSignedContract зберігає підписаний контракт у файл
func saveSignedContract(signedContract []byte) error {
	return ioutil.WriteFile("signed_contract.p7s", signedContract, 0644)
}

// executePythonProgram виконує пайтоновську програму з підписаного контракту
func executePythonProgram(filename string) (string, error) {
	cmd := exec.Command("python", filename)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// handleError обробляє помилки та виводить повідомлення про помилку
func handleError(message string, err error) {
	if err != nil {
		fmt.Println(message, err)
	}
}

// formatPublicKey форматує публічний ключ для виведення на екран
func formatPublicKey(publicKey *rsa.PublicKey) string {
	pubKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return string(pemKey)
}

// formatPrivateKey форматує приватний ключ для виведення на екран
func formatPrivateKey(privateKey *rsa.PrivateKey) string {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return string(pemKey)
}

// formatCertificate форматує сертифікат для виведення на екран
func formatCertificate(cert *x509.Certificate) string {
	certBytes := cert.Raw
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	return string(pemCert)
}

// displayResult виводить результат виконання пайтоновської програми
func displayResult(result string) {
	fmt.Println("Результат виконання пайтоновської програми:")
	fmt.Println(result)
}

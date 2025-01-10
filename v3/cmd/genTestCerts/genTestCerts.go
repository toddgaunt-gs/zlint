package main

/*
 * ZLint Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (

	// "crypto/ecdsa"
	// "crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	"golang.org/x/crypto/cryptobyte"

	//"github.com/zmap/zlint/v3/util"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// Generates a CA, an intermediate, and a leaf certificate and prints their
// OpenSSL textual output to stdout.
func main() {

	ca, err := newTrustAnchor()
	if err != nil {
		panic(err)
	}
	// printCertificate(ca, "Trust Anchor")
	intermediate, err := newIntermediate(ca)
	if err != nil {
		panic(err)
	}
	printCertificate(intermediate, "Intermediate")

	// leaf, err := newLeaf(ca, []*Certificate{intermediate})
	// if err != nil {
	// 	panic(err)
	// }
	// printCertificate(leaf, "Leaf")
	// The following snippets will automatically save the generated certificates to
	// v3/testdata under the provided filename. As that directory is rather large
	// and somewhat unwieldy to navigate, this greatly helps accelerate testdata
	// generation and eliminates common errors
	//
	//err = saveCertificateToTestdata(ca, "PLACEHOLDER.pem")
	//if err != nil {
	//	panic(err)
	//}
	//err = saveCertificateToTestdata(intermediate, "PLACEHOLDER.pem")
	//if err != nil {
	//	panic(err)
	//}
	//err = saveCertificateToTestdata(leaf, "PLACEHOLDER.pem")
	//if err != nil {
	//	panic(err)
	//}
}

// This is NOT a healthy example of a leaf certificate, this is nothing
// more than a self signed certificate with IsCA set to false. Not even any
// basic constraints are defined. Please do not think that this will be
// acceptable to any system, let alone lint particularly well.
// func newLeaf(trustAnchor *Certificate, intermediates []*Certificate) (*Certificate, error) {
// 	var parent *Certificate
// 	if len(intermediates) == 0 {
// 		parent = trustAnchor
// 	} else {
// 		parent = intermediates[len(intermediates)-1]
// 	}
// 	// Edit this template to look like whatever leaf cert you need.
// 	template := x509.Certificate{
// 		Raw:                     nil,
// 		RawTBSCertificate:       nil,
// 		RawSubjectPublicKeyInfo: nil,
// 		RawSubject:              nil,
// 		RawIssuer:               nil,
// 		Signature:               nil,
// 		SignatureAlgorithm:      0,
// 		PublicKeyAlgorithm:      3,
// 		PublicKey:               nil,
// 		Version:                 0,
// 		SerialNumber:            nextSerial(),
// 		Issuer:                  pkix.Name{},
// 		Subject: pkix.Name{
// 			CommonName:           "common_name",
// 			Country:              []string{"GB"},
// 			Locality:             []string{"locality"},
// 			PostalCode:           []string{"postalCode"},
// 			StreetAddress:        []string{"StreetAddress"},
// 			Organization:         []string{"Organization"},
// 			OrganizationalUnit:   []string{"OrganizationalUnit"},
// 			JurisdictionCountry:  []string{"GB"},
// 			JurisdictionLocality: []string{"JurisdictionLocality"},
// 			Surname:              []string{"Surname"},
// 			GivenName:            []string{"GivenName"},
// 			SerialNumber:         "SerialNumber",
// 		},
// 		NotBefore:                   time.Date(9999, 0, 0, 0, 0, 0, 0, time.UTC), // util.RFC5280Date,
// 		NotAfter:                    time.Date(9999, 0, 0, 0, 0, 0, 0, time.UTC),
// 		KeyUsage:                    nil,
// 		Extensions:                  nil,
// 		ExtraExtensions:             nil,
// 		UnhandledCriticalExtensions: nil,
// 		ExtKeyUsage:                 nil,
// 		UnknownExtKeyUsage:          []asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31},
// 		BasicConstraintsValid:       false,
// 		IsCA:                        false,
// 		MaxPathLen:                  0,
// 		MaxPathLenZero:              false,
// 		SubjectKeyId:                nil,
// 		AuthorityKeyId:              nil,
// 		OCSPServer:                  nil,
// 		IssuingCertificateURL:       nil,
// 		DNSNames:                    nil,
// 		EmailAddresses:              nil,
// 		IPAddresses:                 nil,
// 		URIs:                        nil,
// 		PermittedEmailAddresses:     nil,
// 		ExcludedEmailAddresses:      nil,
// 		CRLDistributionPoints:       nil,
// 		PolicyIdentifiers:           []asn1.ObjectIdentifier{{2, 23, 140, 1, 1}},
// 	}
// 	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		return nil, err
// 	}
// 	cert, err := x509.CreateCertificate(rand.Reader, &template, parent.Certificate, key.Public(), parent.private)
// 	if err != nil {
// 		return nil, err
// 	}
// 	c, err := x509.ParseCertificate(cert)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &Certificate{
// 		Certificate: c,
// 		public:      key.Public(),
// 		private:     key,
// 	}, nil
// }

// This is NOT a healthy example of a CA certificate, this is nothing
// more than a self signed certificate with IsCA set to true. Not even any
// basic constraints are defined. Please do not think that this will be
// acceptable to any system, let alone lint particularly well.
func newTrustAnchor() (*Certificate, error) {
	// Edit this template to look like whatever trust anchor you need.
	template := x509.Certificate{
		Raw:                         nil,
		RawTBSCertificate:           nil,
		RawSubjectPublicKeyInfo:     nil,
		RawSubject:                  nil,
		RawIssuer:                   nil,
		Signature:                   nil,
		SignatureAlgorithm:          0,
		PublicKeyAlgorithm:          0,
		PublicKey:                   nil,
		Version:                     0,
		SerialNumber:                nextSerial(),
		Issuer:                      pkix.Name{},
		Subject:                     pkix.Name{},
		NotBefore:                   time.Time{},
		NotAfter:                    time.Date(9999, 0, 0, 0, 0, 0, 0, time.UTC),
		KeyUsage:                    0,
		Extensions:                  nil,
		ExtraExtensions:             nil,
		UnhandledCriticalExtensions: nil,
		ExtKeyUsage:                 nil,
		UnknownExtKeyUsage:          nil,
		BasicConstraintsValid:       true,
		IsCA:                        false,
		MaxPathLen:                  0,
		MaxPathLenZero:              false,
		SubjectKeyId:                nil,
		AuthorityKeyId:              nil,
		OCSPServer:                  nil,
		IssuingCertificateURL:       nil,
		DNSNames:                    nil,
		EmailAddresses:              nil,
		IPAddresses:                 nil,
		URIs:                        nil,
		PermittedEmailAddresses:     nil,
		ExcludedEmailAddresses:      nil,
		CRLDistributionPoints:       nil,
		PolicyIdentifiers:           nil,
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	return &Certificate{
		Certificate: c,
		public:      key.Public(),
		private:     key,
	}, nil
}

// This is NOT a healthy example of an intermediate certificate, this is nothing
// more than a signed certificate with IsCA set to true. Not even any
// basic constraints are defined. Please do not think that this will be
// acceptable to any system, let alone lint particularly well.
func newIntermediate(parent *Certificate) (*Certificate, error) {
	// Edit this template to look like whatever intermediate you need.
	template := x509.Certificate{
		Raw:                     nil,
		RawTBSCertificate:       nil,
		RawSubjectPublicKeyInfo: nil,
		RawSubject:              nil,
		RawIssuer:               nil,
		Signature:               nil,
		SignatureAlgorithm:      0,
		PublicKeyAlgorithm:      0,
		PublicKey:               nil,
		Version:                 0,
		SerialNumber:            nextSerial(),
		Issuer:                  pkix.Name{},
		Subject:                 pkix.Name{},
		NotBefore:               time.Time{},
		NotAfter:                time.Date(9999, 0, 0, 0, 0, 0, 0, time.UTC),
		KeyUsage:                x509.KeyUsageDataEncipherment,
		Extensions:              nil,
		ExtraExtensions: []pkix.Extension{
			{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}, false, encodeASN1()},
		},
		UnhandledCriticalExtensions: nil,
		ExtKeyUsage:                 nil,
		UnknownExtKeyUsage:          nil,
		BasicConstraintsValid:       true,
		IsCA:                        false,
		MaxPathLen:                  0,
		MaxPathLenZero:              false,
		SubjectKeyId:                nil,
		AuthorityKeyId:              nil,
		OCSPServer:                  nil,
		IssuingCertificateURL:       nil,
		DNSNames:                    nil,
		EmailAddresses:              nil,
		IPAddresses:                 nil,
		URIs:                        nil,
		PermittedEmailAddresses:     nil,
		ExcludedEmailAddresses:      nil,
		CRLDistributionPoints:       nil,
		PolicyIdentifiers:           []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 53087, 1, 1}},
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, parent.Certificate, key.Public(), parent.private)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	return &Certificate{
		Certificate: c,
		public:      key.Public(),
		private:     key,
	}, nil
}

type Marshallable interface {
	Marshal(*cryptobyte.Builder, int) error
}

func marshallInnerTypeWithTag(data Marshallable, childTag int) ([]byte, error) {
	var err error
	var bytes []byte
	var builder cryptobyte.Builder
	if err = data.Marshal(&builder, childTag); err != nil {
		return nil, err
	}
	if bytes, err = builder.Bytes(); err != nil {
		return nil, err
	}
	return bytes, nil
}

func openSSLFormatCertificate(cert *Certificate) (string, error) {
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	cmd := exec.Command("openssl", "x509", "-text")
	cmd.Stdin = strings.NewReader(string(block))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// nextSerial is a simple, thread safe, sequential serial number generator.
// Serial numbers begin an 1 and monotonically increase with each call.
var nextSerial = func() func() *big.Int {
	l := sync.Mutex{}
	var serial int64
	return func() *big.Int {
		l.Lock()
		defer l.Unlock()
		serial++
		return big.NewInt(serial)
	}
}()

type Certificate struct {
	*x509.Certificate
	public  interface{}
	private interface{}
}

func printCertificate(certificate *Certificate, header string) {
	fmted, err := openSSLFormatCertificate(certificate)
	if err != nil {
		panic(err)
	}
	fmt.Printf("-------------%s-------------\n", header)
	fmt.Println(fmted)
}

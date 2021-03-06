// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package swim

import (
	"crypto/x509"
	"encoding/pem"
)

// CertPool is a set of certificates.
type CertPool struct {
	bySubjectKeyID map[string][]int
	byName         map[string][]int
	certs          []*x509.Certificate
}

// NewCertPool returns a new, empty CertPool.
func NewCertPool() *CertPool {
	return &CertPool{
		bySubjectKeyID: make(map[string][]int),
		byName:         make(map[string][]int),
	}
}

// unused
// func (s *CertPool) copy() *CertPool {
// 	p := &CertPool{
// 		bySubjectKeyID: make(map[string][]int, len(s.bySubjectKeyID)),
// 		byName:         make(map[string][]int, len(s.byName)),
// 		certs:          make([]*x509.Certificate, len(s.certs)),
// 	}
// 	for k, v := range s.bySubjectKeyID {
// 		indexes := make([]int, len(v))
// 		copy(indexes, v)
// 		p.bySubjectKeyID[k] = indexes
// 	}
// 	for k, v := range s.byName {
// 		indexes := make([]int, len(v))
// 		copy(indexes, v)
// 		p.byName[k] = indexes
// 	}
// 	copy(p.certs, s.certs)
// 	return p
// }

// findPotentialParents returns the indexes of certificates in s which might
// have signed cert. The caller must not modify the returned slice.
// unused
// func (s *CertPool) findPotentialParents(cert *x509.Certificate) []int {
// 	if s == nil {
// 		return nil
// 	}

// 	var candidates []int
// 	if len(cert.AuthorityKeyId) > 0 {
// 		candidates = s.bySubjectKeyID[string(cert.AuthorityKeyId)]
// 	}
// 	if len(candidates) == 0 {
// 		candidates = s.byName[string(cert.RawIssuer)]
// 	}
// 	return candidates
// }

func (s *CertPool) contains(cert *x509.Certificate) bool {
	if s == nil {
		return false
	}

	candidates := s.byName[string(cert.RawSubject)]
	for _, c := range candidates {
		if s.certs[c].Equal(cert) {
			return true
		}
	}

	return false
}

// AddCert adds a certificate to a pool.
func (s *CertPool) AddCert(cert *x509.Certificate) {
	if cert == nil {
		panic("adding nil Certificate to CertPool")
	}

	// Check that the certificate isn't being added twice.
	if s.contains(cert) {
		return
	}

	n := len(s.certs)
	s.certs = append(s.certs, cert)

	if len(cert.SubjectKeyId) > 0 {
		keyID := string(cert.SubjectKeyId)
		s.bySubjectKeyID[keyID] = append(s.bySubjectKeyID[keyID], n)
	}

	name := string(cert.RawSubject)
	s.byName[name] = append(s.byName[name], n)
}

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func (s *CertPool) AppendCertsFromPEM(pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block

		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		s.AddCert(cert)

		ok = true
	}

	return
}

// Subjects returns a list of the DER-encoded subjects of
// all of the certificates in the pool.
//lint:ignore U1001 // compatibility with x509.CertPool.
func (s *CertPool) Subjects() [][]byte {
	res := make([][]byte, len(s.certs))
	for i, c := range s.certs {
		res[i] = c.RawSubject
	}

	return res
}

// Walk runs a supplied function on each certificate in the pool.
func (s *CertPool) Walk(walkFunc func(*x509.Certificate) error) error {
	var err error
	for _, c := range s.certs {
		err = walkFunc(c)
		if err != nil {
			return err
		}
	}

	return nil
}

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/zmap/zcrypto/encoding/asn1"
	"golang.org/x/crypto/cryptobyte"
)

type LogotypeExtn struct {
	CommunityLogos []LogotypeInfo //`asn1:"optional,explicit,tag:0"`
	IssuerLogo     LogotypeInfo   //`asn1:"optional,explicit,tag:1"`
	SubjectLogo    LogotypeInfo   //`asn1:"optional,explicit,tag:2"` //Only this one
	OtherLogos     []LogotypeInfo //`asn1:"optional,explicit,tag:3"`
}

func (l *LogotypeExtn) Marshal(parent *cryptobyte.Builder) error {
	sequence := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Tag:        asn1.TagSequence,
	}

	childTag := 2
	if bytes, err := marshallInnerTypeWithTag(&l.SubjectLogo, childTag); err != nil {
		return err
	} else {
		sequence.Bytes = bytes
	}

	if sequenceDER, err := asn1.Marshal(sequence); err != nil {
		return fmt.Errorf("error marshaling LogotypeExtn: %s", err.Error())
	} else {
		parent.AddBytes(sequenceDER)
	}

	return nil
}

type LogotypeInfo struct {
	Direct   *LogotypeData
	Indirect *LogotypeReference //Dont use
}

// Marshal makes the LogotypeInfo (tag=2 for valid)
func (l *LogotypeInfo) Marshal(parent *cryptobyte.Builder, outerTag int) error {

	if l.Direct != nil && l.Indirect != nil {
		return errors.New("LogotypeInfo must be either direct or indirect")
	}

	choice := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true, // as CHOICE it is a Constructed type and not Primitive type
		Tag:        outerTag,
	}

	var err error
	var bytes []byte
	if l.Direct != nil {
		childTag := 0
		if bytes, err = marshallInnerTypeWithTag(l.Direct, childTag); err != nil {
			return err
		}
	} else {
		childTag := 1
		if bytes, err = marshallInnerTypeWithTag(l.Direct, childTag); err != nil {
			return err
		}
	}
	choice.Bytes = bytes

	if choiceDER, err := asn1.Marshal(choice); err != nil {
		return fmt.Errorf("error marshaling LogotypeInfo: %s", err.Error())
	} else {
		parent.AddBytes(choiceDER)
	}

	return nil
}

type LogotypeData struct {
	Image []LogotypeImage `asn1:"optional"`
	Audio []LogotypeAudio `asn1:"optional,tag:1"`
}

// Marshal makes the LogotypeData a cryptobyte.MarshalingValue
func (l *LogotypeData) Marshal(parent *cryptobyte.Builder, outerTag int) error {
	if l.Image != nil && l.Audio != nil {
		return nil
	}
	logotypeData := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        outerTag,
	}

	var err error
	var imageBytes, audioBytes []byte
	if l.Image != nil {
		if imageBytes, err = asn1.Marshal(l.Image); err != nil {
			return err
		}
		//imageBytes[93] = 22 // Right tag for IA5String format for LogotypeURI instead of UTF8 (12)
	}
	if l.Audio != nil {
		if audioBytes, err = asn1.Marshal(l.Audio); err != nil {
			return err
		}
	}
	logotypeData.Bytes = append(imageBytes, audioBytes...)

	if choiceDER, err := asn1.Marshal(logotypeData); err != nil {
		return fmt.Errorf("error marshaling LogotypeInfo: %s", err.Error())
	} else {
		parent.AddBytes(choiceDER)
	}

	return nil
}

type LogotypeReference struct {
	RefStructHash []HashAlgAndValue
	RefStructURI  string
}

type HashAlgAndValue struct {
	HashAlg   AlgorithmIdentifier
	HashValue []byte
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type LogotypeAudio struct {
	Blabla string
}

type LogotypeImage struct {
	ImageDetails LogotypeDetails
	ImageInfo    LogotypeImageInfo `asn1:"optional"`
}

type LogotypeImageInfo struct {
	Blabla string
}
type LogotypeDetails struct {
	MediaType    string `asn1:"ia5"` //image/svg-xml  IA5String
	LogotypeHash []HashAlgAndValue
	LogotypeURI  LogotypeURI //"data:image/svg+xml;base64,myBase64data"
}

type LogotypeURI struct {
	URI string `asn1:"ia5"`
	// Uncomment this if you want to have more than one image
	//URI2 string `asn1:"ia5"`
}

func encodeASN1() []byte {

	h512 := sha512.New()
	h512.Write([]byte(svgImage))
	sha512Hash := h512.Sum(nil)

	h384 := sha512.New384()
	h384.Write([]byte(svgImage))
	sha384Hash := h384.Sum(nil)

	h256 := sha256.New()
	h256.Write([]byte(svgImage))
	sha256Hash := h256.Sum(nil)
	//_ = sha256Hash

	h1 := sha1.New()
	h1.Write([]byte(svgImage))
	sha1Hash := h1.Sum(nil)
	//_ = sha1Hash

	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(svgImage))
	w.Close()

	encoded := base64.StdEncoding.EncodeToString(b.Bytes())
	_ = encoded

	// Use this if you want a non-gzipped version. This will cause an error with the lint.
	//encoded = base64.StdEncoding.EncodeToString([]byte(svgImage))

	logotypeExtn := LogotypeExtn{
		SubjectLogo: LogotypeInfo{
			Direct: &LogotypeData{
				Image: []LogotypeImage{
					{
						ImageDetails: LogotypeDetails{
							MediaType: "image/svg+xml",
							LogotypeHash: []HashAlgAndValue{
								{AlgorithmIdentifier{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, asn1.NullRawValue}, sha1Hash},
								{AlgorithmIdentifier{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, asn1.NullRawValue}, sha256Hash},
								{AlgorithmIdentifier{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, asn1.NullRawValue}, sha384Hash},
								{AlgorithmIdentifier{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, asn1.NullRawValue}, sha512Hash},
							},
							LogotypeURI: LogotypeURI{
								URI:  fmt.Sprintf("%s%s", "data:image/svg+xml;base64,", encoded),

								// Use this if you want an Empty Image
								//URI: "data:image/svg+xml;base64,",

								// Use this if you want more than one image present
								//URI: "data:image/svg+xml;base64,",
							},
						},
						//ImageInfo: LogotypeImageInfo{"if this field is present then e_vmc_logotype_contents will trigger an error"},
					},
				},
			},
		},
	}

	var builder cryptobyte.Builder
	if err := logotypeExtn.Marshal(&builder); err != nil {
		log.Fatal(err)
		return []byte{}
	}
	if bytes, err := builder.Bytes(); err != nil {
		log.Fatal(err)
		return []byte{}
	} else {
		return bytes
	}

	//if bytes, err := asn1.Marshal(logotypeExtn); err == nil {
	//	var a LogotypeExtn
	//	asn1.Unmarshal(bytes, &a)
	//	fmt.Println(a)
	//	return bytes
	//} else {
	//	log.Fatal(err)
	//	return []byte{}
	//}
}

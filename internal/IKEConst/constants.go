package IKEConst

const (
	CommonScan     = 1
	VulnerableScan = 2
	FullScan       = 3
)

// Versions
const (
	IKEv1 = 0x10
	IKEv2 = 0x20
)

// transform types
const (
	TRANS_ENCR           = 1
	TRANS_PRF            = 2
	TRANS_INTEG          = 3
	TRANS_KE             = 4
	TRANS_ESN            = 5
	IKEv1_TRANS_AUTH     = 3
	IKEv1_TRANS_LIFETYPE = 11

	IKEv1_TRANS_LIFEDURATION = 12
)

// Standard Lengths
const (
	IKE_HEADER_LENGTH         = 28
	IKE_PAYLOAD_HEADER_LENGTH = 4
)

// Encryption algorithms
const (
	ENCR_AES_GCM_8  = 18
	ENCR_AES_GCM_12 = 19
	ENCR_AES_GCM_16 = 20
)

// PRF algorithms
const (
	PRF_HMAC_MD5          = 1
	PRF_HMAC_SHA1         = 2
	PRF_HMAC_TIGER        = 3
	PRF_AES128_XCBC       = 4
	PRF_HMAC_SHA2_256     = 5 //https://www.rfc-editor.org/rfc/rfc4868.html
	PRF_HMAC_SHA2_384     = 6
	PRF_HMAC_SHA2_512     = 7
	PRF_AES128_CMAC       = 8
	PRF_HMAC_STREEBOG_512 = 9
)

// ikev2 DH groups https://www.rfc-editor.org/rfc/rfc3526.html#page-3
// ExchangeTypes
const (
	//IKEV1

	NONE                = 0
	BASE                = 1
	MAIN_MODE           = 2
	AUTH_ONLY           = 3
	AGGRESSIVE_MODE     = 4
	IKEV1_INFORMATIONAL = 5
	QUICK_MODE          = 32
	//IKEv2
	IKE_SA_INIT     = 34
	IKE_AUTH        = 35
	CREATE_CHILD_SA = 36
	INFORMATIONAL   = 37
)

// Payload types
const (
	//IKEv1
	IKEv1_SA    = 1
	P           = 2
	T           = 3
	IKEv1_KE    = 4
	ID          = 5
	H           = 8
	IKEv1_N     = 11
	IKEv1_NONCE = 10
	VID         = 13
	// IKEv2
	SA         = 33
	KE         = 34
	IDi        = 35
	IDr        = 36
	CERT       = 37
	CERTREQ    = 38
	AUTH       = 39
	NI         = 40
	NR         = 40
	N          = 41
	D          = 42
	TSi        = 44
	TSr        = 45
	ENCAndAUTH = 46
)

// Proposal types
const (
	PROP_ISAKMP = 1
)

// Payload types
const (
	PROPOSAL  = 0x02
	TRANSFORM = 0x03
)

// Attribute types
const (
	ATTR_TV        = 0x80
	ATTR_TLV       = 0x00
	ATTR_KEYLENGTH = 14
)

func GetIKEv1EncAlgos() map[uint16]string {
	encAlgos := map[uint16]string{
		1: "DES-CBC",
		2: "IDEA-CBC",
		3: "Blowfish-CBC",
		4: "RC5-R16-B64-CBC",
		5: "3DES-CBC",
		6: "CAST-CBC",
		7: "AES-CBC",
		8: "CAMELLIA-CBC",
	}
	return encAlgos

}
func IKEv1AllEncAlgos() []uint16 {
	return []uint16{1, 2, 3, 4, 5, 6, 7, 8}

}
func IKEv1CommonEncAlgos() []uint16 {
	return []uint16{1, 5, 7, 8}

}
func IKEv1DeprecatedEncAlgos() []uint16 {
	algos := []uint16{1, 2, 3, 4, 5, 6}
	return algos

}
func GetPossibleKeyLengthsForEncIKEv1(id uint16) []uint16 {
	var lengths []uint16
	switch id {
	case 7, 8:
		lengths = []uint16{128, 192, 256}
	default:
		lengths = []uint16{0}

	}
	return lengths
}
func GetIKEv1HashAlgos() map[uint16]string {
	hashAlgos := map[uint16]string{
		1: "MD5",
		2: "SHA",
		3: "Tiger",
		4: "SHA2-256",
		5: "SHA2-384",
		6: "SHA2-512",
	}
	return hashAlgos
}
func IKEv1AllHashAlgos() []uint16 {
	return []uint16{1, 2, 3, 4, 5, 6}

}
func IKEv1CommonHashAlgos() []uint16 {
	return []uint16{1, 2, 4}

}
func IKEv1DeprecatedHashAlgos() []uint16 {
	algos := []uint16{1, 2, 3}
	return algos

}
func GetIKEv1AuthMethods() map[uint16]string {
	authMethods := map[uint16]string{
		1:  "pre-shared key",
		2:  "DSS signatures",
		3:  "RSA signatures",
		4:  "Encryption with RSA",
		5:  "Revised encryption with RSA",
		6:  "Encryption with El-Gamal",
		7:  "Revised encryption with El-Gamal",
		8:  "ECDSA signatures",
		9:  "ECDSA with SHA-256 on the P-256 curve",
		10: "ECDSA with SHA-384 on the P-384 curve",
		11: "ECDSA with SHA-512 on the P-521 curve",
	}
	return authMethods

}
func IKEv1AllAuthMethods() []uint16 {
	return []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

}
func IKEv1CommonAuthMethods() []uint16 {
	return []uint16{1, 3, 8}

}
func IKEv1DeprecatedAuthMethods() []uint16 {
	algos := []uint16{1, 2, 4, 5, 6, 7}
	return algos

}
func GetIKEv1DHGroups() map[uint16]string {
	dhGroups := map[uint16]string{
		1:  "default 768-bit MODP group",
		2:  "alternate 1024-bit MODP group",
		3:  "EC2N group on GP[2^155]",
		4:  "EC2N group on GP[2^185]",
		5:  "1536-bit MODP group",
		6:  "EC2N group over GF[2^163]",
		7:  "EC2N group over GF[2^163]",
		8:  "EC2N group over GF[2^283]",
		9:  "EC2N group over GF[2^283]",
		10: "EC2N group over GF[2^409]",
		11: "EC2N group over GF[2^409]",
		12: "EC2N group over GF[2^571]",
		13: "EC2N group over GF[2^571]",
		14: "2048-bit MODP group",
		15: "3072-bit MODP group",
		16: "4096-bit MODP group",
		17: "6144-bit MODP group",
		18: "8192-bit MODP group",
		19: "256-bit random ECP group",
		20: "384-bit random ECP group",
		21: "521-bit random ECP group",
		22: "1024-bit MODP Group with 160-bit Prime Order Subgroup",
		23: "2048-bit MODP Group with 224-bit Prime Order Subgroup",
		24: "2048-bit MODP Group with 256-bit Prime Order Subgroup",
		25: "192-bit Random ECP Group",
		26: "224-bit Random ECP Group",
		27: "224-bit Brainpool ECP group",
		28: "256-bit Brainpool ECP group",
		29: "384-bit Brainpool ECP group",
		30: "512-bit Brainpool ECP group",
	}
	return dhGroups

}
func IKEv1AllDHGroups() []uint16 {
	return []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30}

}
func IKEv1CommonDHGroups() []uint16 {
	return []uint16{1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21}

}
func IKEv1DeprecatedDHGroups() []uint16 {
	algos := []uint16{1, 2, 3, 4, 5}
	return algos

}

// Returns a map with the ids and corresponding names of all possible IKEv2 encryption algorithms according to IANA (https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml)
func GetIKEv2EncAlgos() map[uint16]string {
	encAlgos := map[uint16]string{
		1:  "ENCR_DES_IV64",
		2:  "ENCR_DES",
		3:  "ENCR_3DES",
		4:  "ENCR_RC5",
		5:  "ENCR_IDEA",
		6:  "ENCR_CAST",
		7:  "ENCR_BLOWFISH",
		8:  "ENCR_3IDEA",
		9:  "ENCR_DES_IV32",
		11: "ENCR_NULL",
		12: "ENCR_AES_CBC",
		13: "ENCR_AES_CTR",
		14: "ENCR_AES_CCM_8",
		15: "ENCR_AES_CCM_12",
		16: "ENCR_AES_CCM_16",
		18: "ENCR_AES_GCM_8",
		19: "ENCR_AES_GCM_12",
		20: "ENCR_AES_GCM_16", //https://www.rfc-editor.org/rfc/rfc4106#ref-GCM, https://www.rfc-editor.org/rfc/rfc5282.html#section-7.1
		21: "ENCR_NULL_AUTH_AES_GMAC",
		23: "ENCR_CAMELLIA_CBC", //https://datatracker.ietf.org/doc/rfc5529/
		//24: "ENCR_CAMELLIA_CTR",
		//	25: ""
		28: "ENCR_CHACHA20_POLY1305", //https://www.rfc-editor.org/rfc/rfc7634.html
		32: "ENCR_KUZNYECHIK_MGM_KTREE",
		33: "ENCR_MAGMA_MGM_KTREE",
	}
	return encAlgos

}
func IKEv2AllEncAlgos() []uint16 {
	return []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 23, 28, 32, 33}

}
func IKEv2CommonEncAlgos() []uint16 {
	return []uint16{2, 3, 12, 13, 18, 19, 20, 23, 28}

}
func IKEv2DeprecatedEncAlgos() []uint16 {
	algos := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 11, 21}
	return algos

}
func GetPossibleKeyLengthsForEncIKEv2(id uint16) []uint16 {
	var lengths []uint16
	switch id {
	case 12, 13, 14, 15, 16, 18, 19, 20, 23:
		lengths = []uint16{128, 192, 256}
	default:
		lengths = []uint16{0}

	}
	return lengths
}
func GetIKEv2PRFAlgos() map[uint16]string {
	prfAlgos := map[uint16]string{
		1: "PRF_HMAC_MD5",
		2: "PRF_HMAC_SHA1",
		3: "PRF_HMAC_TIGER",
		4: "PRF_AES128_XCBC",
		5: "PRF_HMAC_SHA2_256",
		6: "PRF_HMAC_SHA2_384",
		7: "PRF_HMAC_SHA2_512",
		8: "PRF_AES128_CMAC",
		9: "PRF_HMAC_STREEBOG_512",
	}
	return prfAlgos
}
func IKEv2AllPRFAlgos() []uint16 {
	return []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9}

}
func IKEv2CommonPRFAlgos() []uint16 {
	return []uint16{1, 2, 5, 7}

}
func IKEv2DeprecatedPRFAlgos() []uint16 {
	return []uint16{1, 2, 3, 4}

}
func GetIKEv2IntegrityAlgos() map[uint16]string {
	integAlgos := map[uint16]string{
		0:  "NONE", //used when a AEAD enc algo is specified
		1:  "AUTH_HMAC_MD5_96",
		2:  "AUTH_HMAC_SHA1_96",
		3:  "AUTH_DES_MAC",
		4:  "AUTH_KPDK_MD5",
		5:  "AUTH_AES_XCBC_96",
		6:  "AUTH_HMAC_MD5_128",
		7:  "AUTH_HMAC_SHA1_160",
		8:  "AUTH_AES_CMAC_96",
		9:  "AUTH_AES_128_GMAC",
		10: "AUTH_AES_192_GMAC",
		11: "AUTH_AES_256_GMAC",
		12: "AUTH_HMAC_SHA2_256_128",
		13: "AUTH_HMAC_SHA2_384_192",
		14: "AUTH_HMAC_SHA2_512_256",
	}
	return integAlgos

}
func IKEv2AllIntegAlgos() []uint16 {
	return []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}

}
func IKEv2CommonIntegAlgos() []uint16 {
	return []uint16{1, 2, 6, 7, 11, 14}

}
func IKEv2DeprecatedIntegAlgos() []uint16 {
	return []uint16{1, 2, 3, 4, 6, 7}

}
func IKEv2AllKEXAlgos() []uint16 {
	return []uint16{0, 1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34}

}
func IKEv2CommonKEXAlgos() []uint16 {
	return []uint16{2, 5, 14, 16, 18, 19, 20, 21, 31}

}
func IKEv2DeprecatedKEXAlgos() []uint16 {
	return []uint16{0, 1, 2, 5, 22}

}
func GetIKEv2KEXMethods() map[uint16]string {
	kexMethods := map[uint16]string{
		0:  "NONE",
		1:  "768-bit MODP Group",
		2:  "1024-bit MODP Group",
		5:  "1536-bit MODP Group",
		14: "2048-bit MODP Group",
		15: "3072-bit MODP Group",
		16: "4096-bit MODP Group",
		17: "6144-bit MODP Group",
		18: "8192-bit MODP Group",
		19: "256-bit random ECP group", //https://datatracker.ietf.org/doc/html/rfc4753
		20: "384-bit random ECP group",
		21: "521-bit random ECP group",
		22: "1024-bit MODP Group with 160-bit Prime Order Subgroup",
		23: "2048-bit MODP Group with 224-bit Prime Order Subgroup",
		24: "2048-bit MODP Group with 256-bit Prime Order Subgroup",
		25: "192-bit Random ECP Group",
		26: "224-bit Random ECP Group",
		27: "brainpoolP224r1", //https://www.rfc-editor.org/rfc/rfc6954.html
		28: "brainpoolP256r1",
		29: "brainpoolP384r1",
		30: "brainpoolP512r1",
		31: "Curve25519", //https://www.rfc-editor.org/rfc/rfc8031.html
		32: "Curve448",
		33: "GOST3410_2012_256", //https://www.rfc-editor.org/rfc/rfc9385.html
		34: "GOST3410_2012_512",
	}
	return kexMethods

}

// returns the corresponding length of the modulus and therefore the keylength for the kex group in bytes
func GetIKEv2KEXKeyLength(kex uint16) int {
	length := 0
	switch kex {
	case 1:
		length = 96
	case 2:
		length = 128
	case 5:
		length = 192
	case 14:
		length = 256
	case 15:
		length = 384
	case 16:
		length = 512
	case 17:
		length = 768
	case 18:
		length = 1024
	case 19:
		length = 64
	case 20:
		length = 96
	case 21:
		length = 132
	case 22:
		length = 128
	case 23, 24:
		length = 256
	case 25:
		length = 24
	case 26:
		length = 28
	case 27:
		length = 56
	case 28:
		length = 64
	case 29:
		length = 96
	case 30:
		length = 128
	case 31:
		length = 32
	case 32:
		length = 56
	case 33:
		length = 64
	case 34:
		length = 128

	default:
		length = 0

	}
	return length
}

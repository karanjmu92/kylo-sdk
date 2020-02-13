package kylo_sdk

import (
	"encoding/json"
	"github.com/gemalto/requester"
	"github.com/gemalto/requester/httpclient"
	"io/ioutil"
	"kylo-sdk/utility"
	"time"
)

type KeysEndPoint Client

// Resource is the base set of properties shared by most response structs.
type Resource struct {
	ID  string `json:"id"`
	URI string `json:"uri"`

	// All resources are owned by an account (URI)
	Account     string `json:"account"`
	Application string `json:"application"`
	DevAccount  string `json:"devAccount"`
	// All resources have a created timestamp
	// Auto-set by gorm
	CreatedAt time.Time `json:"createdAt"`
}
// CryptoUsageMask type is a Cryptographic Usage Mask defined by KMIP
type CryptoUsageMask uint32

// Key is an ncryptify key
type Key struct {
	Resource
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updatedAt"`
	Material  string    `json:"material,omitempty"`
	// Usage is deprecated, use UsageMask
	Usage string `json:"usage,omitempty" validate:"required,key-usage"`
	// UsageMask replaces Usage
	UsageMask                CryptoUsageMask    `json:"usageMask,omitempty"`
	Meta                     json.RawMessage    `json:"meta"`
	Version                  int                `json:"version"`
	Algorithm                string             `json:"algorithm"`
	Size                     int                `json:"size,omitempty"`
	CurveID                  string             `json:"curveid,omitempty"`
	Format                   string             `json:"format,omitempty"`
	Unexportable             bool               `json:"unexportable"`
	Undeletable              bool               `json:"undeletable"`
	NeverExported            bool               `json:"neverExported"`
	NeverExportable          bool               `json:"neverExportable"`
	EmptyMaterial            bool               `json:"emptyMaterial"`
	PublicKey                string             `json:"publickey,omitempty"`
	DefaultIV                string             `json:"defaultIV,omitempty"`
	Sha1Fingerprint          string             `json:"sha1Fingerprint,omitempty"`
	Sha256Fingerprint        string             `json:"sha256Fingerprint,omitempty"`
	ObjectType               string             `json:"objectType"`
	ActivationDate           *time.Time         `json:"activationDate,omitempty"`
	DeactivationDate         *time.Time         `json:"deactivationDate,omitempty"`
	ArchiveDate              *time.Time         `json:"archiveDate,omitempty"`
	DestroyDate              *time.Time         `json:"destroyDate,omitempty"`
	CompromiseOccurrenceDate *time.Time         `json:"compromiseOccurrenceDate,omitempty"`
	CompromiseDate           *time.Time         `json:"compromiseDate,omitempty"`
	RevocationReason         string             `json:"revocationReason,omitempty"`
	RevocationMessage        string             `json:"revocationMessage,omitempty"`
	ProcessStartDate         *time.Time         `json:"processStartDate,omitempty"`
	ProtectStopDate          *time.Time         `json:"protectStopDate,omitempty"`
	State                    string             `json:"state,omitempty"`
	Aliases                  []KeyAlias         `json:"aliases,omitempty"`
	Links                    []Link             `json:"links,omitempty"`
	CertFields               *CertificateFields `json:"certFields,omitempty"`
	SKInfo                   *SplitKeyInfo      `json:"splitKeyInfo,omitempty"`
	PGPKeyVersion            int                `json:"pgpKeyVersion,omitempty"`
	UUID                     string             `json:"uuid,omitempty"`
	MUID                     string             `json:"muid,omitempty"`
	KeyID                    string             `json:"keyId,omitempty"`
}
// SplitKeyInfo contains information associated with a KMIP split key object.
type SplitKeyInfo struct {
	SKParts             int    `json:"splitKeyParts,omitempty"`
	SKKeyPartIdentifier int    `json:"splitKeyPartIdentifier,omitempty"`
	SKThreshold         int    `json:"splitKeyThreshold,omitempty"`
	SKMethod            int    `json:"splitKeyMethod,omitempty"`
	SKPrimeFieldSize    string `json:"splitKeyPrimeFieldSize,omitempty"`
}

// DNFields decomposes certificate distinguished name
type DNFields struct {
	CommonName         string   `json:"cn,omitempty"`
	Organization       []string `json:"o,omitempty"`
	OrganizationalUnit []string `json:"ou,omitempty"`
	Email              []string `json:"mail,omitempty"`
	Country            []string `json:"c,omitempty"`
	Province           []string `json:"st,omitempty"`
	StreetAddress      []string `json:"street,omitempty"`
	Locality           []string `json:"l,omitempty"`
	UID                []string `json:"uid,omitempty"`
	SerialNumber       string   `json:"sn,omitempty"`
	Title              []string `json:"t,omitempty"`
	DomainComponent    []string `json:"dc,omitempty"`
	DNQualifier        []string `json:"dnq,omitempty"`
}

// CertificateFields contains information that is extracted from a certificate.
// Public key info is not here, but in the Key::Algorithm, Key::Size and Key::PublicKey
type CertificateFields struct {
	CertType                  string    `json:"certType,omitempty"`
	CertLength                int       `json:"certLength,omitempty"`
	X509SerialNumber          string    `json:"x509SerialNumber,omitempty"`
	SerialNumber              string    `json:"serialNumber,omitempty"`
	DigitalSignatureAlgorithm string    `json:"dsalg,omitempty"`
	IssuerDNFields            *DNFields `json:"issuerDNFields,omitempty"`
	SubjectDNFields           *DNFields `json:"subjectDNFields,omitempty"`
	IssuerANFields            *ANFields `json:"issuerANFields,omitempty"`
	SubjectANFields           *ANFields `json:"subjectANFields,omitempty"`
}
// ANFields decomposes certificate alternative name
type ANFields struct {
	DNS          []string `json:"dns,omitempty"`
	IPAddress    []string `json:"ipAddress,omitempty"`
	URI          []string `json:"uri,omitempty"`
	EmailAddress []string `json:"emailAddress,omitempty"`
}


// Link represents a link between the source and target
type Link struct {
	Resource
	UpdatedAt time.Time `json:"updatedAt"`
	Type      LinkType  `json:"type"`
	Source    string    `json:"source"`
	SourceID  string    `json:"sourceID"`
	Target    string    `json:"target"`
	TargetID  string    `json:"targetID"`
	Index     int       `json:"index"`
}
// LinkType type
type LinkType string

// KeyAlias is a structure that holds the KMIP name attribute
type KeyAlias struct {
	Alias string `json:"alias"`
	Type  string `json:"type"`
	Index int    `json:"index"`
}

// PagingInfo is returned by methods which return multiple results.
type PagingInfo struct {
	// Skip is the index of the first result returned.
	Skip int `json:"skip"`
	// Limit is the max number of results returned.
	Limit int `json:"limit"`
	// Total is the total number of results matching the query.
	Total int `json:"total"`
	// Messages contains warning messages about query parameters which were
	// not supported or understood
	Messages []string `json:"messages,omitempty"`
}

// FindKeysResponse is the response to commands that return a set of keys
type FindKeysResponse struct {
	PagingInfo
	Keys []Key `json:"resources"`
}

// ListKeysParams are the params to find keys
type ListKeysParams struct {
	Skip              int             `json:"-" url:"skip,omitempty"`
	Limit             int             `json:"-" url:"limit,omitempty"`
	Name              string          `json:"-" url:"name,omitempty"`
	State             string          `json:"-" url:"state,omitempty"`
	Alias             string          `json:"-" url:"alias,omitempty"`
	LinkType          string          `json:"-" url:"linkType,omitempty"`
	Fields            string          `json:"-" url:"fields,omitempty"`
	UsageMask         CryptoUsageMask `json:"-" url:"usageMask,omitempty"`
	Meta              *string         `json:"-" url:"metaContains,omitempty"`
	ObjectType        string          `json:"-" url:"objectType,omitempty"`
	Sha1Fingerprint   string          `json:"-" url:"sha1Fingerprint,omitempty"`
	Sha256Fingerprint string          `json:"-" url:"sha256Fingerprint,omitempty"`
	Algorithm         string          `json:"-" url:"algorithm,omitempty"`
	Size              int             `json:"-" url:"size,omitempty"`
	ID                string          `json:"-" url:"id,omitempty"`
	UUID              string          `json:"-" url:"uuid,omitempty"`
	MUID              string          `json:"-" url:"muid,omitempty"`
	KeyID             string          `json:"-" url:"keyId,omitempty"`
}

// CreateKeyParams are the params to create a key
type CreateKeyParams struct {
	Name          string `json:"name,omitempty" url:"-"`
	PublicKeyName string `json:"publicKeyName,omitempty" url:"-"`
	// Usage is deprecated, use UsageMask
	Usage string `json:"usage,omitempty" url:"-"`
	// UsageMask replaces Usage
	UsageMask           CryptoUsageMask            `json:"usageMask,omitempty" url:"-"`
	Meta                interface{}                `json:"meta,omitempty" url:"-"`
	Algorithm           string                     `json:"algorithm,omitempty" url:"-"`
	Size                int                        `json:"size,omitempty" url:"-"`
	CurveID             string                     `json:"curveid,omitempty" url:"-"`
	Format              string                     `json:"format,omitempty" url:"-"`
	Unexportable        bool                       `json:"unexportable,omitempty" url:"-"`
	Undeletable         bool                       `json:"undeletable,omitempty" url:"-"`
	NeverExported       bool                       `json:"neverExported,omitempty" url:"-"`
	NeverExportable     bool                       `json:"neverExportable,omitempty" url:"-"`
	Material            string                     `json:"material,omitempty" url:"-"`
	ReturnExisting      bool                       `json:"-" url:"returnExisting,omitempty"`
	IncludeMaterial     bool                       `json:"-" url:"includeMaterial,omitempty"`
	EmptyMaterial       bool                       `json:"emptyMaterial,omitempty" url:"-"`
	DefaultIV           string                     `json:"defaultIV,omitempty" url:"-"`
	ActivationDate      *time.Time                 `json:"activationDate,omitempty" url:"-"`
	DeactivationDate    *time.Time                 `json:"deactivationDate,omitempty" url:"-"`
	ArchiveDate         *time.Time                 `json:"archiveDate,omitempty" url:"-"`
	ProcessStartDate    *time.Time                 `json:"processStartDate,omitempty" url:"-"`
	ProtectStopDate     *time.Time                 `json:"protectStopDate,omitempty" url:"-"`
	State               string                     `json:"state,omitempty" url:"-"`
	Aliases             []KeyAlias                 `json:"aliases,omitempty" url:"-"`
	PublicKeyParameters KeyPostPublicKeyParameters `json:"publicKeyParameters,omitempty" url:"-"`
	WrapKeyParams
	CertType                 string                `json:"certType,omitempty" url:"-"`
	ObjectType               string                `json:"objectType,omitempty" url:"-"`
	Password                 string                `json:"password,omitempty" url:"-"`
	HkdfCreateParameters     *HkdfCreateParameters `json:"hkdfCreateParameters,omitempty" url:"-"`
	UUID                     string                `json:"uuid,omitempty" url:"-"`
	MUID                     string                `json:"muid,omitempty" url:"-"`
	KeyID                    string                `json:"keyId,omitempty" url:"-"`
	ID                       string                `json:"id,omitempty" url:"-"`
	XTS                      bool                  `json:"xts,omitempty" url:"-"`
	GenerateKeyID            bool                  `json:"generateKeyId,omitempty" url:"-"`
	DestroyDate              *time.Time            `json:"destroyDate,omitempty" url:"-"`
	CompromiseOccurrenceDate *time.Time            `json:"compromiseOccurrenceDate,omitempty" url:"-"`
	CompromiseDate           *time.Time            `json:"compromiseDate,omitempty" url:"-"`
	RevocationReason         string                `json:"revocationReason,omitempty" url:"-"`
	RevocationMessage        string                `json:"revocationMessage,omitempty" url:"-"`
}

// HkdfParameters : Common parameters of HKDF in Create and Export Key
type HkdfParameters struct {
	HashAlgorithm string `json:"hashAlgorithm,omitempty"`

	//Random HEX bytes of any length
	Salt string `json:"salt,omitempty"`

	//Random HEX bytes of any length
	Info string `json:"info,omitempty"`
}

// HkdfCreateParameters : For Key creation using HKDF
type HkdfCreateParameters struct {
	HkdfParameters
	//Key name used as a master key for HKDF
	IkmKeyName string `json:"ikmKeyName,omitempty"`
}

// WrapKeyParams used for wrapping the material in the response
type WrapKeyParams struct {
	WrapPublicKey        string `json:"wrapPublicKey,omitempty" url:"-"`
	WrapKeyName          string `json:"wrapKeyName,omitempty" url:"-"`
	Padded               bool   `json:"padded,omitempty" url:"-"`
	WrapPublicKeyPadding string `json:"wrapPublicKeyPadding,omitempty" url:"-"`
}

// KeyPostPublicKeyParameters - Post body in create and export key requests for public key.
type KeyPostPublicKeyParameters struct {
	Name             string          `json:"name"`
	UsageMask        CryptoUsageMask `json:"usageMask"`
	Meta             interface{}     `json:"meta,omitempty"`
	ActivationDate   *time.Time      `json:"activationDate,omitempty"`
	DeactivationDate *time.Time      `json:"deactivationDate,omitempty"`
	ArchiveDate      *time.Time      `json:"archiveDate,omitempty"`
	State            string          `json:"state,omitempty"`
	Aliases          []KeyAlias      `json:"aliases,omitempty"`
	Unexportable     *bool           `json:"unexportable,omitempty" url:"-"`
	Undeletable      *bool           `json:"undeletable,omitempty" url:"-"`
}

//List keys
func (p *KeysEndPoint) ListKeys(params *ListKeysParams) (*FindKeysResponse, error) {
	url := utility.GetBaseURL(p.Config.KyloIP) + utility.KMIPPrefix
	jwt, err := utility.GetJWT(p.Config.KyloIP, p.Config.KyloUser, p.Config.KyloPassword)
	if err != nil{
		return nil, err
	}
	resp, err := requester.Send(
		requester.Get(url),
		requester.BearerAuth(jwt),
		requester.Client(httpclient.SkipVerify(p.Config.SkipSSLVerify)),
	)
	if err != nil {
		return nil, err
	}
	var keysResponse FindKeysResponse
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body,&keysResponse)

	return &keysResponse, nil
}

// Create a key
func (p *KeysEndPoint) CreateKey( params *CreateKeyParams) (*Key, error) {
	url := utility.GetBaseURL(p.Config.KyloIP) + utility.KMIPPrefix
	jwt, err := utility.GetJWT(p.Config.KyloIP, p.Config.KyloUser, p.Config.KyloPassword)
	if err != nil {
		return nil, err
	}
	resp, err := requester.Send(
		requester.Post(url),
		requester.BearerAuth(jwt),
		requester.Body(params),
		requester.Client(httpclient.SkipVerify(p.Config.SkipSSLVerify)),
	)
	if err != nil {
		return nil, err
	}
	var key Key
	body, err := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body,&key)
	return &key, nil
}

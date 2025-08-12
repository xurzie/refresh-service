package service

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/0xPolygonID/refresh-service/providers/flexiblehttp"
	core "github.com/iden3/go-iden3-core/v2"
	jsonproc "github.com/iden3/go-schema-processor/v2/json"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/processor"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

var (
	ErrCredentialNotUpdatable = errors.New("not updatable")
	errIndexSlotsNotUpdated   = errors.New("no index fields were updated")
)

type RefreshService struct {
	issuerService  *IssuerService
	documentLoader ld.DocumentLoader
	providers      flexiblehttp.FactoryFlexibleHTTP
}

func NewRefreshService(
	issuerService *IssuerService,
	documentLoader ld.DocumentLoader,
	providers flexiblehttp.FactoryFlexibleHTTP,
) *RefreshService {
	return &RefreshService{
		issuerService:  issuerService,
		documentLoader: documentLoader,
		providers:      providers,
	}
}

type credentialRequest struct {
	CredentialSchema  string                     `json:"credentialSchema"`
	Type              string                     `json:"type"`
	CredentialSubject map[string]interface{}     `json:"credentialSubject"`
	Expiration        int64                      `json:"expiration"`
	RefreshService    *verifiable.RefreshService `json:"refreshService,omitempty"`
	RevNonce          *uint64                    `json:"revNonce,omitempty"`
	DisplayMethod     *verifiable.DisplayMethod  `json:"displayMethod,omitempty"`
}

func (rs *RefreshService) Process(
	ctx context.Context,
	issuer, owner, id string,
) (*verifiable.W3CCredential, error) {
	log.Printf("🔄 Starting refresh for credential ID: %s", id)

	credential, err := rs.issuerService.GetClaimByID(issuer, id)
	if err != nil {
		log.Printf("❌ Failed to fetch credential from issuer: %v", err)
		return nil, err
	}

	credentialJSON, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		log.Printf("❌ Failed to marshal credential: %v", err)
		return nil, err
	}
	log.Printf("🧾 Full credential:\n%s", credentialJSON)

	log.Printf("🔎 Parsed credential — issuer: '%s', type: '%v', subject: %+v",
		credential.Issuer, credential.Type, credential.CredentialSubject)

	if credential.CredentialSubject == nil {
		log.Printf("❌ Credential subject is nil")
		return nil, errors.New("credential subject is nil")
	}

	log.Printf("✅ Retrieved credential with subject: %+v", credential.CredentialSubject)

	if err := isUpdatable(credential); err != nil {
		log.Printf("⚠️ Credential not updatable: %v", err)
		return nil, errors.Wrapf(ErrCredentialNotUpdatable, "credential '%s': %v", credential.ID, err)
	}

	if err := checkOwnerShip(credential, owner); err != nil {
		log.Printf("⚠️ Ownership mismatch: %v", err)
		return nil, errors.Wrapf(ErrCredentialNotUpdatable, "credential '%s': %v", credential.ID, err)
	}

	credentialBytes, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	subjectType, ok := credential.CredentialSubject["type"].(string)
	if !ok || subjectType == "" {
		log.Printf("❌ Subject type not found or invalid")
		return nil, errors.New("invalid or missing type in credentialSubject")
	}
	log.Printf("🔍 Subject type: %s", subjectType)

	credentialType, err := merklize.Options{
		DocumentLoader: rs.documentLoader,
	}.TypeIDFromContext(credentialBytes, subjectType)
	if err != nil {
		log.Printf("❌ Failed to compute TypeID from context: %v", err)
		return nil, err
	}

	log.Printf("🔍 CredentialType (config key): %s", credentialType)

	flexibleHTTP, err := rs.providers.ProduceFlexibleHTTP(credentialType)
	if err != nil {
		log.Printf("❌ No flexible provider found: %v", err)
		return nil, errors.Wrapf(ErrCredentialNotUpdatable, "for credential '%s' no provider: %v", credential.ID, err)
	}

	updatedFields, err := flexibleHTTP.Provide(credential.CredentialSubject)
	if err != nil {
		log.Printf("❌ Error while providing updated fields: %v", err)
		return nil, err
	}
	log.Printf("📥 Updated fields: %+v", updatedFields)

	if err := rs.isUpdatedIndexSlots(ctx, credential, credential.CredentialSubject, updatedFields); err != nil {
		log.Printf("❌ Index slots not updated: %v", err)
		return nil, errors.Wrapf(ErrCredentialNotUpdatable, "index update fail: %v", err)
	}

	for k, v := range updatedFields {
		credential.CredentialSubject[k] = v
	}

	revNonce, err := extractRevocationNonce(credential)
	if err != nil {
		log.Printf("❌ Revocation nonce error: %v", err)
		return nil, err
	}

	credReq := credentialRequest{
		CredentialSchema:  credential.CredentialSchema.ID,
		Type:              subjectType,
		CredentialSubject: credential.CredentialSubject,
		Expiration:        time.Now().Add(flexibleHTTP.Settings.TimeExpiration).Unix(),
		RefreshService:    credential.RefreshService,
		RevNonce:          &revNonce,
		DisplayMethod:     credential.DisplayMethod,
	}

	log.Printf("🚀 Sending refreshed credential request: %+v", credReq)

	refreshedID, err := rs.issuerService.CreateCredential(issuer, credReq)
	if err != nil {
		log.Printf("❌ Failed to create refreshed credential: %v", err)
		return nil, err
	}
	log.Printf("✅ Refreshed credential ID: %s", refreshedID)

	return rs.issuerService.GetClaimByID(issuer, refreshedID)
}

func isUpdatable(credential *verifiable.W3CCredential) error {
	if credential.Expiration.After(time.Now()) {
		return errors.New("not expired")
	}
	idVal, ok := credential.CredentialSubject["id"].(string)
	if !ok || strings.TrimSpace(idVal) == "" {
		return errors.New("credential subject does not have a valid id")
	}
	return nil
}

func checkOwnerShip(credential *verifiable.W3CCredential, owner string) error {
	if credential.CredentialSubject["id"] != owner {
		return errors.New("not owner of the credential")
	}
	return nil
}

func (rs *RefreshService) isUpdatedIndexSlots(
	ctx context.Context,
	credential *verifiable.W3CCredential,
	oldValues, newValues map[string]interface{},
) error {
	claim, err := jsonproc.Parser{}.ParseClaim(ctx, *credential, &processor.CoreClaimOptions{
		MerklizerOpts: []merklize.MerklizeOption{
			merklize.WithDocumentLoader(rs.documentLoader),
		},
	})
	if err != nil {
		return errors.Errorf("invalid w3c credential: %v", err)
	}

	merklizedRootPosition, err := claim.GetMerklizedPosition()
	if err != nil {
		return errors.Errorf("failed to get merklized position: %v", err)
	}

	switch merklizedRootPosition {
	case core.MerklizedRootPositionIndex:
		return nil
	case core.MerklizedRootPositionValue:
		return errIndexSlotsNotUpdated
	case core.MerklizedRootPositionNone:
		credentialBytes, err := rs.loadContexts(credential.Context)
		if err != nil {
			return errors.Errorf("failed to load contexts: %v", err)
		}
		for k, v := range oldValues {
			if k == "type" || k == "id" {
				continue
			}
			slotIndex, err := jsonproc.Parser{}.GetFieldSlotIndex(
				k, oldValues["type"].(string), credentialBytes)
			if err != nil && strings.Contains(err.Error(), "not specified in serialization info") {
				return nil
			} else if err != nil {
				return err
			}
			if (slotIndex == 2 || slotIndex == 3) && v != newValues[k] {
				return nil
			}
		}
	}
	return errIndexSlotsNotUpdated
}

func (rs *RefreshService) loadContexts(contexts []string) ([]byte, error) {
	type uploadedContexts struct {
		Contexts []interface{} `json:"@context"`
	}
	var res uploadedContexts
	for _, context := range contexts {
		remoteDocument, err := rs.documentLoader.LoadDocument(context)
		if err != nil {
			return nil, err
		}
		document, ok := remoteDocument.Document.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid context")
		}
		ldContext, ok := document["@context"]
		if !ok {
			return nil, errors.New("@context key word didn't find")
		}
		if v, ok := ldContext.([]interface{}); ok {
			res.Contexts = append(res.Contexts, v...)
		} else {
			res.Contexts = append(res.Contexts, ldContext)
		}
	}
	return json.Marshal(res)
}

func extractRevocationNonce(credential *verifiable.W3CCredential) (uint64, error) {
	credentialStatusInfo, ok := credential.CredentialStatus.(map[string]interface{})
	if !ok {
		return 0, errors.New("invalid credential status")
	}
	nonce, ok := credentialStatusInfo["revocationNonce"]
	if !ok {
		return 0, errors.New("revocationNonce not found in credential status")
	}
	n, ok := nonce.(float64)
	if !ok {
		return 0, errors.New("revocationNonce is not a number")
	}
	return uint64(n), nil
}

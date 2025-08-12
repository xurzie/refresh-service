package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/0xPolygonID/refresh-service/logger"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/pkg/errors"
)

var (
	ErrIssuerNotSupported = errors.New("issuer is not supported")
	ErrGetClaim           = errors.New("failed to get claim")
	ErrCreateClaim        = errors.New("failed to create claim")
)

// IssuerService is service for communication with issuer node
type IssuerService struct {
	supportedIssuers map[string]string
	issuerBasicAuth  map[string]string
	do               http.Client
}

func NewIssuerService(
	supportedIssuers map[string]string,
	issuerBasicAuth map[string]string,
	client *http.Client,
) *IssuerService {
	if client == nil {
		client = http.DefaultClient
	}
	return &IssuerService{
		supportedIssuers: supportedIssuers,
		issuerBasicAuth:  issuerBasicAuth,
		do:               *client,
	}
}

func (is *IssuerService) GetClaimByID(issuerDID, claimID string) (*verifiable.W3CCredential, error) {
	issuerNode, err := is.getIssuerURL(issuerDID)
	if err != nil {
		return nil, err
	}
	logger.DefaultLogger.Infof("use issuer node '%s' for issuer '%s'", issuerNode, issuerDID)

	getRequest, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/v2/identities/%s/credentials/%s", issuerNode, issuerDID, claimID),
		http.NoBody,
	)
	if err != nil {
		return nil, errors.Wrapf(ErrGetClaim,
			"failed to create http request: '%v'", err)
	}
	if err := is.setBasicAuth(issuerDID, getRequest); err != nil {
		return nil, err
	}

	resp, err := is.do.Do(getRequest)
	if err != nil {
		return nil, errors.Wrapf(ErrGetClaim,
			"failed http GET request: '%v'", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrapf(ErrGetClaim,
			"invalid status code: '%d'", resp.StatusCode)
	}

	// 📥 Читаем и логируем тело
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(ErrGetClaim, "failed to read response body: '%v'", err)
	}
	log.Printf("📡 Raw response from issuer node (%s):\n%s", getRequest.URL.String(), string(rawBody))

	resp.Body = io.NopCloser(bytes.NewBuffer(rawBody))

	var response struct {
		VC verifiable.W3CCredential `json:"vc"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, errors.Wrapf(ErrGetClaim,
			"failed to decode response: '%v'", err)
	}
	log.Printf("✅ Parsed VC: %+v\n", response.VC)
	return &response.VC, nil
}

func (is *IssuerService) CreateCredential(issuerDID string, credentialRequest credentialRequest) (
	id string,
	err error,
) {
	issuerNode, err := is.getIssuerURL(issuerDID)
	if err != nil {
		return id, err
	}
	logger.DefaultLogger.Infof("use issuer node '%s' for issuer '%s'", issuerNode, issuerDID)

	body := bytes.NewBuffer([]byte{})
	err = json.NewEncoder(body).Encode(credentialRequest)
	if err != nil {
		return id, errors.Wrapf(ErrCreateClaim,
			"credential request serialization error")
	}

	postRequest, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/v2/identities/%s/credentials", issuerNode, issuerDID),
		body,
	)
	if err != nil {
		return id, errors.Wrapf(ErrCreateClaim,
			"failed to create http request: '%v'", err)
	}
	if err := is.setBasicAuth(issuerDID, postRequest); err != nil {
		return id, err
	}

	resp, err := is.do.Do(postRequest)
	if err != nil {
		return id, errors.Wrapf(ErrCreateClaim,
			"failed http POST request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return id, errors.Wrap(ErrCreateClaim,
			"invalid status code")
	}
	responseBody := struct {
		ID string `json:"id"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&responseBody)
	if err != nil {
		return id, errors.Wrapf(ErrCreateClaim,
			"failed to decode response: %v", err)
	}
	return responseBody.ID, nil
}

func (is *IssuerService) getIssuerURL(issuerDID string) (string, error) {
	url, ok := is.supportedIssuers[issuerDID]
	if !ok {
		url, ok = is.supportedIssuers["*"]
		if !ok {
			return "", errors.Wrapf(ErrIssuerNotSupported, "id '%s'", issuerDID)
		}
	}
	return url, nil
}

func (is *IssuerService) setBasicAuth(issuerDID string, request *http.Request) error {
	if is.issuerBasicAuth == nil {
		return nil
	}
	namepass, ok := is.issuerBasicAuth[issuerDID]
	if !ok {
		globalNamepass, ok := is.issuerBasicAuth["*"]
		if !ok {
			logger.DefaultLogger.Warnf("issuer '%s' not found in basic auth map", issuerDID)
			return nil
		}
		namepass = globalNamepass
	}

	namepassPair := strings.Split(namepass, ":")
	if len(namepassPair) != 2 {
		return errors.Errorf("invalid basic auth: %q", namepass)
	}

	request.SetBasicAuth(namepassPair[0], namepassPair[1])
	return nil
}

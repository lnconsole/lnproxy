package lnproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/websocket"
)

const (
	EXPIRY_BUFFER    = 300
	FEE_BASE_MSAT    = 1000
	FEE_PPM          = 9000
	MIN_AMOUNT_MSAT  = 100000
	CLTV_DELTA_ALPHA = 3
	CLTV_DELTA_BETA  = 6
	// Should be set to the same as the node's `--max-cltv-expiry` setting (default: 2016)
	MAX_CLTV_DELTA = 2016
)

var (
	lndHost      *url.URL
	lndTlsConfig *tls.Config
	lndClient    *http.Client

	macaroon string
	err      error

	invoiceCh chan Status
	paymentCh chan Status
)

type Status struct {
	Bolt11 string
	Status string
}

func Init(
	macaroonHex string,
	lndHostStr string,
	tlsCertPath string,
	invCh chan Status,
	pmntCh chan Status,
) error {
	invoiceCh = invCh
	paymentCh = pmntCh

	/* handle macaroon */
	macaroon = macaroonHex

	/* handle lndhost */
	lndHost, err = url.Parse(lndHostStr)
	if err != nil {
		return err
	}
	// If this is not set then websocket errors:
	lndHost.Path = "/"

	/* handle tls cert */
	if tlsCertPath == "" {
		lndTlsConfig = &tls.Config{}
	} else {
		lndCert, err := os.ReadFile(tlsCertPath)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(lndCert)
		lndTlsConfig = &tls.Config{RootCAs: caCertPool}
	}

	lndClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: lndTlsConfig,
		},
	}

	return nil
}

type PaymentRequest struct {
	PaymentHash     string `json:"payment_hash"`
	Timestamp       int64  `json:"timestamp,string"`
	Expiry          int64  `json:"expiry,string"`
	Description     string `json:"description"`
	DescriptionHash string `json:"description_hash"`
	NumMsat         uint64 `json:"num_msat,string"`
	CltvExpiry      int64  `json:"cltv_expiry,string"`
	Features        map[string]struct {
		Name       string `json:"name"`
		IsRequired bool   `json:"is_required"`
		IsKnown    bool   `json:"is_known"`
	} `json:"features"`
}

func DecodePaymentRequest(invoice string) (*PaymentRequest, error) {
	req, err := http.NewRequest(
		"GET",
		lndHost.JoinPath("v1/payreq", invoice).String(),
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)

	resp, err := lndClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		return nil, fmt.Errorf("unknown v1/payreq error: %#v", x)
	}

	dec := json.NewDecoder(resp.Body)
	p := PaymentRequest{}
	err = dec.Decode(&p)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &p, nil
}

type WrappedPaymentRequest struct {
	Memo            string `json:"memo,omitempty"`
	Hash            []byte `json:"hash"`
	ValueMsat       uint64 `json:"value_msat,string"`
	DescriptionHash []byte `json:"description_hash,omitempty"`
	Expiry          int64  `json:"expiry,string"`
	CltvExpiry      int64  `json:"cltv_expiry,string"`
}

func WrapPaymentRequest(p *PaymentRequest, max_fee_msat uint64) (*WrappedPaymentRequest, error) {
	for flag, feature := range p.Features {
		switch flag {
		case "8", "9", "14", "15", "16", "17":
		default:
			log.Printf("unhandled feature flag: %s\n\t%v\n", flag, feature)
			if feature.IsRequired {
				return nil, fmt.Errorf("cannot wrap %s invoices", feature.Name)
			}
		}
	}
	q := WrappedPaymentRequest{}
	if p.DescriptionHash != "" {
		description_hash, err := hex.DecodeString(p.DescriptionHash)
		if err != nil {
			return nil, err
		}
		q.DescriptionHash = description_hash
	} else {
		q.Memo = p.Description
	}
	hash, err := hex.DecodeString(p.PaymentHash)
	if err != nil {
		return nil, err
	}
	q.Hash = hash
	if p.NumMsat == 0 {
		q.ValueMsat = 0
	} else {
		if max_fee_msat == 0 {
			q.ValueMsat = p.NumMsat + (p.NumMsat*FEE_PPM)/1_000_000 + FEE_BASE_MSAT
		} else {
			q.ValueMsat = p.NumMsat + max_fee_msat
		}
	}
	q.Expiry = p.Timestamp + p.Expiry - time.Now().Unix() - EXPIRY_BUFFER
	if q.Expiry < 0 {
		err = fmt.Errorf("%s", "payment request expiration is too close.")
		return nil, err
	}
	q.CltvExpiry = p.CltvExpiry*CLTV_DELTA_BETA + CLTV_DELTA_ALPHA
	if q.CltvExpiry >= MAX_CLTV_DELTA {
		return nil, fmt.Errorf("cltv_expiry is too long")
	}
	return &q, nil
}

func AddWrappedInvoice(p *WrappedPaymentRequest) (string, error) {
	params, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(params)
	req, err := http.NewRequest(
		"POST",
		lndHost.JoinPath("v2/invoices/hodl").String(),
		buf,
	)
	if err != nil {
		return "", err
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := lndClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		if x, ok := x.(map[string]interface{}); ok {
			if x["message"] == "invoice with payment hash already exists" {
				return "", fmt.Errorf("%s", "Wrapped invoice with that payment hash already exists")
			}
		}
		return "", fmt.Errorf("unknown v2/invoices/hodl error: %#v", x)
	}
	dec := json.NewDecoder(resp.Body)
	pr := struct {
		PaymentRequest string `json:"payment_request"`
	}{}
	err = dec.Decode(&pr)
	if err != nil && err != io.EOF {
		return "", err
	}

	return pr.PaymentRequest, nil
}

func WatchWrappedInvoice(p *WrappedPaymentRequest, wrapped_invoice string, original_invoice string, max_fee_msat uint64) {
	header := http.Header(make(map[string][]string, 1))
	header.Add("Grpc-Metadata-Macaroon", macaroon)
	loc := *lndHost
	if loc.Scheme == "https" {
		loc.Scheme = "wss"
	} else {
		loc.Scheme = "ws"
	}
	origin := *lndHost
	origin.Scheme = "http"

	ws, err := websocket.DialConfig(&websocket.Config{
		Location:  loc.JoinPath("v2/invoices/subscribe", base64.URLEncoding.EncodeToString(p.Hash)),
		Origin:    &origin,
		TlsConfig: lndTlsConfig,
		Header:    header,
		Version:   13,
	})
	if err != nil {
		log.Println("Error while subscribing to invoice:", p, err)
		return
	}
	err = websocket.JSON.Send(ws, struct{}{})
	if err != nil {
		log.Println("Error while subscribing to invoice:", p, err)
		return
	}
	for {
		message := struct {
			Result struct {
				State       string `json:"state"`
				AmtPaidMsat uint64 `json:"amt_paid_msat,string"`
			} `json:"result"`
		}{}
		err = websocket.JSON.Receive(ws, &message)
		if err != nil && err != io.EOF {
			log.Println("Error while reading from invoice status lnd socket:", p, err)
			return
		}

		switch message.Result.State {
		case "OPEN":
			continue
		case "ACCEPTED":
			notifyInvoiceStatus(wrapped_invoice, "ACCEPTED")
			SettleWrappedInvoice(p, message.Result.AmtPaidMsat, wrapped_invoice, original_invoice, max_fee_msat)
			return
		case "SETTLED", "CANCELED":
			notifyInvoiceStatus(wrapped_invoice, message.Result.State)
			log.Printf("Invoice %s before payment.\n", message.Result.State)
			return
		default:
			log.Printf("Unknown invoice status: %s\n", message.Result.State)
			return
		}
	}
}

func CancelWrappedInvoice(hash []byte, wrapped_invoice string) {
	params, _ := json.Marshal(
		struct {
			PaymentHash []byte `json:"payment_hash"`
		}{
			PaymentHash: hash,
		},
	)
	buf := bytes.NewBuffer(params)
	req, err := http.NewRequest(
		"POST",
		lndHost.JoinPath("v2/invoices/cancel").String(),
		buf,
	)
	if err != nil {
		log.Println("Error while canceling invoice:", hash, err)
		return
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := lndClient.Do(req)
	if err != nil {
		log.Println("Error while canceling invoice:", hash, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		log.Println("Unknown v2/invoices/cancel error:", x)
		return
	}
	dec := json.NewDecoder(resp.Body)
	var x interface{}
	if err := dec.Decode(&x); err != nil && err != io.EOF {
		log.Println("Unknown v2/invoices/cancel error:", err)
	}
	if xmap, ok := x.(map[string]interface{}); !ok || len(xmap) != 0 {
		log.Println("Unknown v2/invoices/cancel response:", x)
	}

	notifyInvoiceStatus(wrapped_invoice, "CANCELED")
}

func SettleWrappedInvoice(p *WrappedPaymentRequest, paid_msat uint64, wrapped_invoice string, original_invoice string, max_fee_msat uint64) {
	var amt_msat uint64
	if max_fee_msat == 0 {
		max_fee_msat = (paid_msat * FEE_PPM) / 1_000_000
	}
	if p.ValueMsat == 0 {
		amt_msat = paid_msat - max_fee_msat
		if amt_msat < MIN_AMOUNT_MSAT {
			CancelWrappedInvoice(p.Hash, wrapped_invoice)
			return
		}
	}
	params := struct {
		Invoice           string  `json:"payment_request"`
		AmtMsat           uint64  `json:"amt_msat,omitempty,string"`
		TimeoutSeconds    int64   `json:"timeout_seconds"`
		FeeLimitMsat      uint64  `json:"fee_limit_msat,string"`
		NoInflightUpdates bool    `json:"no_inflight_updates"`
		CltvLimit         int32   `json:"cltv_limit"`
		Amp               bool    `json:"amp"`
		TimePref          float64 `json:"time_pref"`
	}{
		Invoice:           original_invoice,
		AmtMsat:           amt_msat,
		TimeoutSeconds:    p.Expiry - time.Now().Unix(),
		FeeLimitMsat:      max_fee_msat,
		NoInflightUpdates: true,
		CltvLimit:         int32(p.CltvExpiry - CLTV_DELTA_ALPHA),
		Amp:               false,
		TimePref:          0.9,
	}

	header := http.Header(make(map[string][]string, 1))
	header.Add("Grpc-Metadata-Macaroon", macaroon)
	loc := *lndHost
	if loc.Scheme == "https" {
		loc.Scheme = "wss"
	} else {
		loc.Scheme = "ws"
	}
	q := url.Values{}
	q.Set("method", "POST")
	loc.RawQuery = q.Encode()
	origin := *lndHost
	origin.Scheme = "http"

	ws, err := websocket.DialConfig(&websocket.Config{
		Location:  loc.JoinPath("v2/router/send"),
		Origin:    &origin,
		TlsConfig: lndTlsConfig,
		Header:    header,
		Version:   13,
	})
	if err != nil {
		log.Println("Error while dialing socket for payment status:", p, err)
		return
	}

	notifyPaymentStatus(original_invoice, "IN_FLIGHT")

	err = websocket.JSON.Send(ws, params)
	if err != nil {
		log.Println("Error while dialing socket for payment status:", p, err)
		return
	}

	var preimage string

InFlight:
	for {
		message := struct {
			Result struct {
				Status   string `json:"status"`
				PreImage string `json:"payment_preimage"`
			} `json:"result"`
		}{}
		err = websocket.JSON.Receive(ws, &message)
		if err != nil && err != io.EOF {
			log.Println("Error while receiving from socket for payment status:", p, err)
			return
		}

		switch message.Result.Status {
		case "FAILED":
			notifyPaymentStatus(original_invoice, "FAILED")
			CancelWrappedInvoice(p.Hash, wrapped_invoice)
			return
		case "UNKNOWN", "IN_FLIGHT":
			time.Sleep(500 * time.Millisecond)
		case "SUCCEEDED":
			notifyPaymentStatus(original_invoice, "SUCCEEDED")
			preimage = message.Result.PreImage
			log.Printf("preimage (%d): %s\n", paid_msat/1000, preimage)
			break InFlight
		default:
			log.Println("Unknown payment status:", message.Result.Status, p)
		}

		if err == io.EOF {
			log.Println("Unexpected EOF while watching invoice")
			continue
		}
	}

	preimage2, err := hex.DecodeString(preimage)
	if err != nil {
		log.Panicln("Error decoding preimage", err)
	}
	params2, err := json.Marshal(struct {
		PreImage []byte `json:"preimage"`
	}{
		PreImage: preimage2,
	})
	if err != nil {
		log.Panicln(err)
	}
	buf := bytes.NewBuffer(params2)
	req, err := http.NewRequest(
		"POST",
		lndHost.JoinPath("v2/invoices/settle").String(),
		buf,
	)
	if err != nil {
		log.Panicln(err)
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := lndClient.Do(req)
	if err != nil {
		log.Panicln(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		log.Panicln(fmt.Errorf("unknown v2/invoices/settle error: %#v", x))
	}
	dec := json.NewDecoder(resp.Body)

	var x interface{}
	if err := dec.Decode(&x); err != nil && err != io.EOF {
		log.Panicln(err)
	}
	if xmap, ok := x.(map[string]interface{}); !ok || len(xmap) != 0 {
		log.Println(fmt.Errorf("unknown v2/invoices/settle response: %#v", x))
	}

	notifyInvoiceStatus(wrapped_invoice, "SETTLED")
}

func Wrap(invoice string, max_fee_msat uint64) (string, error) {
	p, err := DecodePaymentRequest(invoice)
	if err != nil {
		return "", err
	}
	q, err := WrapPaymentRequest(p, max_fee_msat)
	if err != nil {
		return "", err
	}
	i, err := AddWrappedInvoice(q)
	if err != nil {
		return "", err
	}
	go WatchWrappedInvoice(q, i, invoice, max_fee_msat)
	return i, nil
}

func notifyInvoiceStatus(bolt11 string, status string) {
	go func() {
		invoiceCh <- Status{
			Bolt11: bolt11,
			Status: status,
		}
	}()
}

func notifyPaymentStatus(bolt11 string, status string) {
	go func() {
		paymentCh <- Status{
			Bolt11: bolt11,
			Status: status,
		}
	}()
}

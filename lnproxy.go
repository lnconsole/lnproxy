package main

// import (
// 	"encoding/hex"
// 	"encoding/json"
// 	"flag"
// 	"fmt"
// 	"io"
// 	"log"
// 	"net/http"
// 	"os"
// 	"regexp"
// 	"strconv"

// 	lnproxy "github.com/lnconsole/lnproxy/lib"
// )

// const (
// 	MIN_CUSTOM_FEE_MSAT = 1000
// )

// var (
// 	httpPort      = flag.String("port", "4747", "http port over which to expose api")
// 	lndHostString = flag.String("lnd", "https://127.0.0.1:8080", "host for lnd's REST api")
// 	lndCertPath   = flag.String(
// 		"lnd-cert",
// 		".lnd/tls.cert",
// 		"lnd's self-signed cert (set to empty string for no-rest-tls=true)")
// )

// var validPath = regexp.MustCompile("^/api/(lnbc.*1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)")

// func apiHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Access-Control-Allow-Origin", "*")
// 	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
// 	m := validPath.FindStringSubmatch(r.URL.Path)
// 	if m == nil {
// 		http.NotFound(w, r)
// 		return
// 	}

// 	var max_fee_msat uint64
// 	max_fee_msat_string := r.URL.Query().Get("routing_msat")
// 	if max_fee_msat_string != "" {
// 		var err error
// 		max_fee_msat, err = strconv.ParseUint(max_fee_msat_string, 10, 64)
// 		if err != nil {
// 			http.Error(w, "Invalid custom routing budget", http.StatusBadRequest)
// 			return
// 		}
// 		if max_fee_msat < MIN_CUSTOM_FEE_MSAT {
// 			http.Error(w, "Custom routing budget too small", http.StatusBadRequest)
// 			return
// 		}
// 	}
// 	i, err := lnproxy.Wrap(m[1], max_fee_msat)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	fmt.Fprintf(w, "%s", i)
// }

// func specApiHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Access-Control-Allow-Origin", "*")
// 	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")

// 	var x map[string]interface{}
// 	err := json.NewDecoder(r.Body).Decode(&x)
// 	if err != nil {
// 		b, _ := io.ReadAll(r.Body)
// 		log.Println("Body is not JSON object:", b)
// 		json.NewEncoder(w).Encode(makeJsonError("Body is not JSON object"))
// 		return
// 	}
// 	invoice, ok := x["invoice"]
// 	if !ok {
// 		json.NewEncoder(w).Encode(makeJsonError("Body needs an invoice field"))
// 		return
// 	}
// 	invoice_string, ok := invoice.(string)
// 	if !ok {
// 		json.NewEncoder(w).Encode(makeJsonError("Invoice field must be a string"))
// 		return
// 	}

// 	p, err := lnproxy.DecodePaymentRequest(invoice_string)
// 	if err != nil {
// 		log.Println("Invalid invoice", err)
// 		json.NewEncoder(w).Encode(makeJsonError("Invalid invoice"))
// 		return
// 	}

// 	var max_fee_msat uint64
// 	if routing_msat, ok := x["routing_msat"]; ok {
// 		routing_msat_string, ok := routing_msat.(string)
// 		if !ok {
// 			json.NewEncoder(w).Encode(makeJsonError("Routing budget field must be a string"))
// 			return
// 		}
// 		max_fee_msat, err = strconv.ParseUint(routing_msat_string, 10, 64)
// 		if err != nil {
// 			json.NewEncoder(w).Encode(makeJsonError("Invalid routing budget"))
// 			return
// 		}
// 		if max_fee_msat < MIN_CUSTOM_FEE_MSAT {
// 			json.NewEncoder(w).Encode(makeJsonError("Routing budget too small"))
// 			return
// 		}
// 	}

// 	if description, ok := x["description"]; ok {
// 		description_string, ok := description.(string)
// 		if !ok {
// 			json.NewEncoder(w).Encode(makeJsonError("Description field must be a string"))
// 			return
// 		}
// 		p.Description = description_string
// 		p.DescriptionHash = ""
// 	}

// 	if description_hash, ok := x["description_hash"]; ok {
// 		description_hash_string, ok := description_hash.(string)
// 		if !ok {
// 			json.NewEncoder(w).Encode(makeJsonError("Description hash field must be a string"))
// 			return
// 		}
// 		p.DescriptionHash = description_hash_string
// 		p.Description = ""
// 	}

// 	q, err := lnproxy.WrapPaymentRequest(p, max_fee_msat)
// 	if err != nil {
// 		log.Println("Error while wrapping", err)
// 		json.NewEncoder(w).Encode(makeJsonError("Internal error"))
// 		return
// 	}

// 	wrapped_invoice, err := lnproxy.AddWrappedInvoice(q)
// 	if err != nil {
// 		log.Println("Error while adding wrapped", err)
// 		json.NewEncoder(w).Encode(makeJsonError("Internal error"))
// 		return
// 	}

// 	go lnproxy.WatchWrappedInvoice(q, wrapped_invoice, invoice_string, max_fee_msat)

// 	json.NewEncoder(w).Encode(struct {
// 		WrappedInvoice string `json:"proxy_invoice"`
// 	}{
// 		WrappedInvoice: wrapped_invoice,
// 	})

// }

// type JsonError struct {
// 	Status string `json:"status"`
// 	Reason string `json:"reason"`
// }

// func makeJsonError(reason string) JsonError {
// 	return JsonError{
// 		Status: "ERROR",
// 		Reason: reason,
// 	}
// }

// func main() {
// 	flag.Usage = func() {
// 		fmt.Fprintf(flag.CommandLine.Output(), `usage: %s [flags] lnproxy.macaroon
//   lnproxy.macaroon
// 	Path to lnproxy macaroon. Generate it with:
// 		lncli bakemacaroon --save_to lnproxy.macaroon \
// 			uri:/lnrpc.Lightning/DecodePayReq \
// 			uri:/lnrpc.Lightning/LookupInvoice \
// 			uri:/invoicesrpc.Invoices/AddHoldInvoice \
// 			uri:/invoicesrpc.Invoices/SubscribeSingleInvoice \
// 			uri:/invoicesrpc.Invoices/CancelInvoice \
// 			uri:/invoicesrpc.Invoices/SettleInvoice \
// 			uri:/routerrpc.Router/SendPaymentV2
// `, os.Args[0])
// 		flag.PrintDefaults()
// 		os.Exit(2)
// 	}

// 	flag.Parse()
// 	if len(flag.Args()) != 1 {
// 		flag.Usage()
// 		os.Exit(2)
// 	}

// 	macaroonBytes, err := os.ReadFile(flag.Args()[0])
// 	if err != nil {
// 		fmt.Fprintf(flag.CommandLine.Output(), "Unable to read lnproxy macaroon file: %v\n", err)
// 		os.Exit(2)
// 	}

// 	err = lnproxy.Init(hex.EncodeToString(macaroonBytes), *lndHostString, *lndCertPath)
// 	if err != nil {
// 		fmt.Fprintf(flag.CommandLine.Output(), "Unable to read lnd tls certificate file: %v\n", err)
// 		os.Exit(2)
// 	}

// 	http.HandleFunc("/spec", specApiHandler)
// 	http.HandleFunc("/api/", apiHandler)

// 	log.Fatalln(http.ListenAndServe("localhost:"+*httpPort, nil))
// }

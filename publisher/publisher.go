package publisher

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/honeycombio/honeyelb/options"
	"github.com/honeycombio/honeyelb/state"
	"github.com/honeycombio/honeytail/event"
	"github.com/honeycombio/libhoney-go"
	"github.com/honeycombio/urlshaper"
)

const (
	AWSElasticLoadBalancerFormat = "aws_elb"
	AWSCloudFrontWebFormat       = "aws_cf_web"
)

var (
	// 2017-07-31T20:30:57.975041Z spline_reticulation_lb 10.11.12.13:47882 10.3.47.87:8080 0.000021 0.010962 0.000016 200 200 766 17 "PUT https://api.simulation.io:443/reticulate/spline/1 HTTP/1.1" "libhoney-go/1.3.3" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2
	logFormat = []byte(fmt.Sprintf(`log_format %s '$timestamp $elb $client_authority $backend_authority $request_processing_time $backend_processing_time $response_processing_time $elb_status_code $backend_status_code $received_bytes $sent_bytes "$request" "$user_agent" $ssl_cipher $ssl_protocol';
log_format %s '$timestamp $x_edge_location $sc_bytes $c_ip $cs_method $cs_host $cs_uri_stem $sc_status $cs_referer $cs_user_agent $cs_uri_query $cs_cookie $x_edge_result_type $x_edge_request_id $x_host_header $cs_protocol $cs_bytes $time_taken $x_forwarded_for $ssl_protocol $ssl_cipher $x_edge_response_result_type $cs_protocol_version';`, AWSElasticLoadBalancerFormat, AWSCloudFrontWebFormat))
	libhoneyInitialized = false
	formatFileName      string
)

func init() {
	// Set up the log format file for parsing in the future.
	formatFile, err := ioutil.TempFile("", "honeytail_fmt_file")
	if err != nil {
		logrus.Fatal(err)
	}

	if _, err := formatFile.Write(logFormat); err != nil {
		logrus.Fatal(err)
	}

	if err := formatFile.Close(); err != nil {
		logrus.Fatal(err)
	}

	formatFileName = formatFile.Name()
}

type Publisher interface {
	// Publish accepts an io.Reader and scans it line-by-line, parses the
	// relevant event from each line (using EventParser), and sends to the
	// target (Honeycomb).
	Publish(f state.DownloadedObject) error
}

type EventParser interface {
	// ParseEvents runs in a background goroutine and parses the downloaded
	// object, sending the events parsed from it further down the pipeline
	// using the output channel. er
	ParseEvents(obj state.DownloadedObject, out chan<- event.Event) error

	// DynSample dynamically samples events, reading them from `eventsCh`
	// and sending them to `sampledCh`. Behavior is dependent on the
	// publisher implementation, e.g., some fields might matter more for
	// ELB than for CloudFront.
	DynSample(in <-chan event.Event, out chan<- event.Event)
}

// HoneycombPublisher implements Publisher and sends the entries provided to
// Honeycomb. Publisher allows us to have only one point of entry to sending
// events to Honeycomb (if desired), as well as isolate line parsing, sampling,
// and URL sub-parsing logic.
type HoneycombPublisher struct {
	Stater              state.Stater
	EventParser         EventParser
	APIHost             string
	SampleRate          int
	FinishedObjects     chan string
	parsedCh, sampledCh chan event.Event
}

func NewHoneycombPublisher(opt *options.Options, stater state.Stater, eventParser EventParser) *HoneycombPublisher {
	hp := &HoneycombPublisher{
		Stater:          stater,
		EventParser:     eventParser,
		FinishedObjects: make(chan string),
	}

	if !libhoneyInitialized {
		libhoney.Init(libhoney.Config{
			MaxBatchSize:  500,
			SendFrequency: 100 * time.Millisecond,
			WriteKey:      opt.WriteKey,
			Dataset:       opt.Dataset,
			SampleRate:    uint(opt.SampleRate),
			APIHost:       opt.APIHost,
		})
		libhoneyInitialized = true
	}

	hp.parsedCh = make(chan event.Event)
	hp.sampledCh = make(chan event.Event)

	go sendEventsToHoneycomb(hp.sampledCh)
	go hp.EventParser.DynSample(hp.parsedCh, hp.sampledCh)

	return hp
}

func sendEventsToHoneycomb(in <-chan event.Event) {
	shaper := requestShaper{&urlshaper.Parser{}}
	for ev := range in {
		shaper.Shape("request", &ev)
		libhEv := libhoney.NewEvent()
		libhEv.Timestamp = ev.Timestamp
		if err := libhEv.Add(ev.Data); err != nil {
			logrus.WithFields(logrus.Fields{
				"event": ev,
				"error": err,
			}).Error("Unexpected error adding data to libhoney event")
		}
		// sampling is handled by the nginx parser
		if err := libhEv.SendPresampled(); err != nil {
			logrus.WithFields(logrus.Fields{
				"event": ev,
				"error": err,
			}).Error("Unexpected error event to libhoney send")
		}
	}
}

func (hp *HoneycombPublisher) Publish(downloadedObj state.DownloadedObject) error {
	if err := hp.EventParser.ParseEvents(downloadedObj, hp.parsedCh); err != nil {
		return err
	}

	// Clean up the downloaded object.
	// TODO: Should always be done?
	if err := os.Remove(downloadedObj.Filename); err != nil {
		return fmt.Errorf("Error cleaning up downloaded object %s: %s", downloadedObj.Filename, err)
	}

	if err := hp.Stater.SetProcessed(downloadedObj.Object); err != nil {
		return fmt.Errorf("Error setting state of object as processed: %s", err)
	}

	return nil
}

// Close flushes outstanding sends
func (hp *HoneycombPublisher) Close() {
	libhoney.Close()
}

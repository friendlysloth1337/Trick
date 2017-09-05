package publisher

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/honeycombio/dynsampler-go"
	"github.com/honeycombio/honeyelb/options"
	"github.com/honeycombio/honeyelb/state"
	"github.com/honeycombio/honeytail/event"
	"github.com/honeycombio/honeytail/parsers/nginx"
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
	// relevant event from each line, and sends to the target (Honeycomb)
	Publish(f state.DownloadedObject) error
}

// HoneycombPublisher implements Publisher and sends the entries provided to
// Honeycomb. Publisher allows us to have only one point of entry to sending
// events to Honeycomb (if desired), as well as isolate line parsing, sampling,
// and URL sub-parsing logic.
type HoneycombPublisher struct {
	state.Stater
	APIHost         string
	LogFormat       string
	SampleRate      int
	nginxParser     *nginx.Parser
	FinishedObjects chan string
	sampler         dynsampler.Sampler
}

func NewHoneycombPublisher(opt *options.Options, stater state.Stater, logFormatName string) *HoneycombPublisher {
	hp := &HoneycombPublisher{
		Stater:          stater,
		nginxParser:     &nginx.Parser{},
		LogFormat:       logFormatName,
		FinishedObjects: make(chan string),
	}

	nginxParserOpts := &nginx.Options{
		ConfigFile:    formatFileName,
		TimeFieldName: "timestamp",
		LogFormatName: logFormatName,
		NumParsers:    runtime.NumCPU(),
	}

	switch logFormatName {
	case AWSElasticLoadBalancerFormat:
		nginxParserOpts.TimeFieldFormat = "2006-01-02T15:04:05.9999Z"
	case AWSCloudFrontWebFormat:
		nginxParserOpts.TimeFieldFormat = "2006-01-02T15:04:05"
	}

	// TODO: How to determine proper timestamp format. It will be different for different formats.
	hp.nginxParser.Init(nginxParserOpts)

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

	hp.sampler = &dynsampler.AvgSampleRate{
		ClearFrequencySec: 300,
		GoalSampleRate:    opt.SampleRate,
	}

	if err := hp.sampler.Start(); err != nil {
		logrus.Error(err)
	}
	return hp
}

type requestShaper struct {
	pr *urlshaper.Parser
}

// Nicked directly from github.com/honeycombio/honeytail/leash.go
func (rs *requestShaper) Shape(field string, ev *event.Event) {
	if val, ok := ev.Data[field]; ok {
		// start by splitting out method, uri, and version
		parts := strings.Split(val.(string), " ")
		var path string
		if len(parts) == 3 {
			// treat it as METHOD /path HTTP/1.X
			ev.Data[field+"_method"] = parts[0]
			ev.Data[field+"_protocol_version"] = parts[2]
			path = parts[1]
		} else {
			// treat it as just the /path
			path = parts[0]
		}

		// next up, get all the goodies out of the path
		res, err := rs.pr.Parse(path)
		if err != nil {
			// couldn't parse it, just pass along the event
			logrus.WithError(err).Error("Couldn't parse request")
			return
		}
		ev.Data[field+"_uri"] = res.URI
		ev.Data[field+"_path"] = res.Path
		if res.Query != "" {
			ev.Data[field+"_query"] = res.Query
		}
		ev.Data[field+"_shape"] = res.Shape
		if res.QueryShape != "" {
			ev.Data[field+"_queryshape"] = res.QueryShape
		}
	}
}

func (h *HoneycombPublisher) dynSample(eventsCh <-chan event.Event, sampledCh chan<- event.Event) {
	for ev := range eventsCh {
		// TODO(nathanleclaire): Sampling fields should be done for
		// integrations other than just ELB.

		// use backend_status_code and elb_status_code to set sample rate
		var key string
		if backendStatusCode, ok := ev.Data["backend_status_code"]; ok {
			if bsc, ok := backendStatusCode.(int); ok {
				key = fmt.Sprintf("%d", bsc)
			} else {
				key = "0"
			}
		}
		if elbStatusCode, ok := ev.Data["elb_status_code"]; ok {
			if esc, ok := elbStatusCode.(int); ok {
				key = fmt.Sprintf("%s_%d", key, esc)
			}
		}

		// Make sure sample rate is per-ELB
		if elbName, ok := ev.Data["elb"]; ok {
			if name, ok := elbName.(string); ok {
				key = fmt.Sprintf("%s_%s", key, name)
			}
		}

		rate := h.sampler.GetSampleRate(key)
		if rate <= 0 {
			logrus.WithField("rate", rate).Error("Sample should not be less than zero")
			rate = 1
		}
		if rand.Intn(rate) == 0 {
			ev.SampleRate = rate
			sampledCh <- ev
		}
	}
}

func (h *HoneycombPublisher) sample(eventsCh <-chan event.Event) chan event.Event {
	sampledCh := make(chan event.Event, runtime.NumCPU())
	go h.dynSample(eventsCh, sampledCh)
	return sampledCh
}

func sendEvents(eventsCh <-chan event.Event) {
	shaper := requestShaper{&urlshaper.Parser{}}
	for ev := range eventsCh {
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
	linesCh := make(chan string, runtime.NumCPU())
	eventsCh := make(chan event.Event, runtime.NumCPU())
	go hp.nginxParser.ProcessLines(linesCh, eventsCh, nil)

	var (
		r   io.Reader
		err error
	)

	f, err := os.Open(downloadedObj.Filename)
	if err != nil {
		return err
	}

	// TODO: Interface
	if hp.LogFormat == AWSCloudFrontWebFormat {
		r, err = gzip.NewReader(r)
		if err != nil {
			return err
		}
	} else {
		r = f
	}

	scanner := bufio.NewScanner(r)
	sampledCh := hp.sample(eventsCh)
	go sendEvents(sampledCh)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		splitLine := strings.Fields(line)

		// date and time are two separate fields instead of only one
		// timestamp field, so join them together..
		// TODO: Interface
		if hp.LogFormat == AWSCloudFrontWebFormat {
			// Join together first two items with "T" in between as
			// a new first item and "delete" the second item.
			splitLine = append([]string{splitLine[0] + "T" + splitLine[1]}, splitLine[2:]...)
		}

		// nginx parser is fickle about whitespace, so ensure that only
		// one space exists between fields
		line = strings.Join(splitLine, " ")

		linesCh <- strings.Join(splitLine, " ")
	}

	// Clean up the downloaded object.
	if err := os.Remove(f.Name()); err != nil {
		return fmt.Errorf("Error cleaning up downloaded object %s: %s", f.Name(), err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("Error closing downloaded object file: %s", err)
	}

	if scanner.Err() == nil {
		if err := hp.SetProcessed(downloadedObj.Object); err != nil {
			return fmt.Errorf("Error setting state of object as processed: %s", err)
		}
	}

	return err
}

// Close flushes outstanding sends
func (hp *HoneycombPublisher) Close() {
	libhoney.Close()
}

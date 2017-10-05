package publisher

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	dynsampler "github.com/honeycombio/dynsampler-go"
	"github.com/honeycombio/honeyelb/state"
	"github.com/honeycombio/honeytail/event"
	"github.com/honeycombio/honeytail/parsers/nginx"
)

type CloudFrontEventParser struct {
	sampler dynsampler.Sampler
}

func NewCloudFrontEventParser(sampleRate int) *CloudFrontEventParser {
	ep := &CloudFrontEventParser{
		sampler: &dynsampler.AvgSampleRate{
			ClearFrequencySec: 300,
			GoalSampleRate:    sampleRate,
		},
	}

	if err := ep.sampler.Start(); err != nil {
		logrus.WithField("err", err).Fatal("Couldn't start dynamic sampler")
	}

	return ep
}

func (ep *CloudFrontEventParser) ParseEvents(obj state.DownloadedObject, out chan<- event.Event) error {
	np := &nginx.Parser{}
	err := np.Init(&nginx.Options{
		ConfigFile:      formatFileName,
		TimeFieldName:   "timestamp",
		TimeFieldFormat: "2006-01-02T15:04:05",
		LogFormatName:   AWSCloudFrontWebFormat,
		NumParsers:      runtime.NumCPU(),
	})
	if err != nil {
		logrus.Fatal("Can't initialize the nginx parser")
	}

	linesCh := make(chan string)
	eventsCh := make(chan event.Event)

	go np.ProcessLines(linesCh, eventsCh, nil)

	f, err := os.Open(obj.Filename)
	if err != nil {
		return err
	}

	defer f.Close()

	r, err := gzip.NewReader(f)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(r)
	nLines := 0
	timer := time.NewTimer(time.Second)

	for scanner.Scan() {
		nLines++
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		splitLine := strings.Fields(line)

		// Date and time are two separate fields instead of only one
		// timestamp field, so join them together..
		//
		// We join together the first two items with "T" in between as
		// a new first item and "delete" the second item.
		//
		// Yeah it's ugly, but we don't have many other options with
		// the nginx parser and Amazon's quirky format.
		splitLine = append([]string{splitLine[0] + "T" + splitLine[1]}, splitLine[2:]...)

		// nginx parser is fickle about whitespace, so the join ensures
		// that only one space exists between fields
		linesCh <- strings.Join(splitLine, " ")

		select {
		case <-timer.C:
			return fmt.Errorf("nginx parser didn't successfully parse every line presented to it. # done so far: %d", nLines)
		case ev := <-eventsCh:
			logrus.Debug("sent on eventsCh")
			out <- ev
		}
		timer.Reset(time.Second)
	}

	return nil
}

func (ep *CloudFrontEventParser) DynSample(in <-chan event.Event, out chan<- event.Event) {
	for ev := range in {
		var key string
		if backendStatusCode, ok := ev.Data["sc-status"]; ok {
			if bsc, ok := backendStatusCode.(int); ok {
				key = fmt.Sprintf("%d", bsc)
			} else {
				key = "0"
			}
		}

		// Make sure sample rate is per-distribution (cs is the domain
		// name of the CloudFront distribution)
		if distributionDomain, ok := ev.Data["cs"]; ok {
			if name, ok := distributionDomain.(string); ok {
				key = fmt.Sprintf("%s_%s", key, name)
			}
		}

		rate := ep.sampler.GetSampleRate(key)
		if rate <= 0 {
			logrus.WithField("rate", rate).Error("Sample should not be less than zero")
			rate = 1
		}
		if rand.Intn(rate) == 0 {
			ev.SampleRate = rate
			out <- ev
		}
	}
}

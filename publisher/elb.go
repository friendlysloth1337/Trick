package publisher

import (
	"bufio"
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

type ELBEventParser struct {
	sampler dynsampler.Sampler
}

func NewELBEventParser(sampleRate int) *ELBEventParser {
	ep := &ELBEventParser{
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

func (ep *ELBEventParser) ParseEvents(obj state.DownloadedObject, out chan<- event.Event) error {
	np := &nginx.Parser{}
	err := np.Init(&nginx.Options{
		ConfigFile:      formatFileName,
		TimeFieldName:   "timestamp",
		TimeFieldFormat: "2006-01-02T15:04:05.9999Z",
		LogFormatName:   AWSElasticLoadBalancerFormat,
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

	scanner := bufio.NewScanner(f)
	nLines := 0
	timer := time.NewTimer(time.Second)

	for scanner.Scan() {
		nLines++
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		linesCh <- line
		select {
		case <-timer.C:
			return fmt.Errorf("nginx parser didn't successfully parse every line presented to it. # done so far: %d", nLines)
		case ev := <-eventsCh:
			out <- ev
		}
		timer.Reset(time.Second)
	}

	return scanner.Err()

}

func (ep *ELBEventParser) DynSample(in <-chan event.Event, out chan<- event.Event) {
	for ev := range in {
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

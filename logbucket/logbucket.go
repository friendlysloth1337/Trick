package logbucket

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/honeycombio/honeyelb/meta"
	"github.com/honeycombio/honeyelb/state"
)

const (
	AWSElasticLoadBalancing     = "elasticloadbalancing"
	AWSApplicationLoadBalancing = "elasticloadbalancingv2"
	AWSCloudFront               = "cloudfront"
	AWSCloudTrail               = "cloudtrail"
)

type ObjectDownloader interface {
	fmt.Stringer

	// ObjectPrefix allows the downloaded to efficiently lookup objects
	// based on prefix (unique to each AWS service).
	ObjectPrefix(day time.Time) string

	// Bucket will return the name of the bucket we are downloading the
	// objects from
	Bucket() string
}

// Wrapper struct used to unite the specific structs with common methods.
type Downloader struct {
	state.Stater
	ObjectDownloader
	Sess              *session.Session
	DownloadedObjects chan state.DownloadedObject
	ObjectsToDownload chan *s3.Object
}

func NewDownloader(sess *session.Session, stater state.Stater, downloader ObjectDownloader) *Downloader {
	return &Downloader{
		Stater:            stater,
		ObjectDownloader:  downloader,
		Sess:              sess,
		DownloadedObjects: make(chan state.DownloadedObject),
		ObjectsToDownload: make(chan *s3.Object),
	}
}

type ELBDownloader struct {
	Prefix, BucketName, AccountID, Region, LBName string
}

type CloudFrontDownloader struct {
	Prefix, BucketName, DistributionID string
}

func NewCloudFrontDownloader(bucketName, bucketPrefix, distID string) *CloudFrontDownloader {
	return &CloudFrontDownloader{
		BucketName:     bucketName,
		Prefix:         bucketPrefix,
		DistributionID: distID,
	}
}

func (d *CloudFrontDownloader) ObjectPrefix(day time.Time) string {
	dayPath := day.Format("2006-01-02")
	return d.Prefix + "/" + d.DistributionID + "." + dayPath
}

func (d *CloudFrontDownloader) String() string {
	return d.DistributionID
}

func (d *CloudFrontDownloader) Bucket() string {
	return d.BucketName
}

func NewELBDownloader(sess *session.Session, bucketName, bucketPrefix, lbName string) *ELBDownloader {
	metadata := meta.Data(sess)
	return &ELBDownloader{
		AccountID:  metadata.AccountID,
		Region:     metadata.Region,
		BucketName: bucketName,
		Prefix:     bucketPrefix,
		LBName:     lbName,
	}
}

// pass in time.Now().UTC()
func (d *ELBDownloader) ObjectPrefix(day time.Time) string {
	dayPath := day.Format("/2006/01/02")
	return d.Prefix + "/AWSLogs/" + d.AccountID + "/" + AWSElasticLoadBalancing + "/" + d.Region + dayPath +
		"/" + d.AccountID + "_" + AWSElasticLoadBalancing + "_" + d.Region + "_" + d.LBName
}

func (d *ELBDownloader) String() string {
	return d.LBName
}

func (d *ELBDownloader) Bucket() string {
	return d.BucketName
}

func (d *Downloader) downloadObject(obj *s3.Object) error {
	logrus.WithFields(logrus.Fields{
		"key":           *obj.Key,
		"size":          *obj.Size,
		"from_time_ago": time.Since(*obj.LastModified),
		"entity":        d.String(),
	}).Info("Downloading access logs from object")

	f, err := ioutil.TempFile("", "hc-entity-ingest")
	if err != nil {
		return fmt.Errorf("Error creating tmp file: %s", err)
	}

	downloader := s3manager.NewDownloader(d.Sess)

	nBytes, err := downloader.Download(f, &s3.GetObjectInput{
		Bucket: aws.String(d.Bucket()),
		Key:    aws.String(*obj.Key),
	})
	if err != nil {
		return fmt.Errorf("Error downloading object file: %s", err)
	}

	logrus.WithFields(logrus.Fields{
		"bytes":  nBytes,
		"file":   f.Name(),
		"entity": d.String(),
	}).Info("Successfully downloaded object")

	d.DownloadedObjects <- state.DownloadedObject{
		Filename: f.Name(),
		Object:   *obj.Key,
	}

	return nil
}

func (d *Downloader) downloadObjects() {
	for obj := range d.ObjectsToDownload {
		if err := d.downloadObject(obj); err != nil {
			logrus.Error(err)
		}
	}
}

func (d *Downloader) accessLogBucketPageCallback(processedObjects []string, bucketResp *s3.ListObjectsOutput, lastPage bool) bool {
	// TODO: This sort doesn't work as originally intended if the paging
	// comes into play. Consider removing, or gathering all desired objects
	// as a result of the callback, _then_ sorting and iterating over them.
	sort.Slice(bucketResp.Contents, func(i, j int) bool {
		return (*bucketResp.Contents[i].LastModified).After(
			*bucketResp.Contents[j].LastModified,
		)
	})

	for _, obj := range bucketResp.Contents {
		for _, processedObj := range processedObjects {
			if *obj.Key == processedObj {
				logrus.WithField("object", processedObj).Info("Already processed, skipping")
				return true
			}
		}

		// Backfill one hour backwards by default
		//
		// TODO(nathanleclaire): Make backfill interval configurable.
		if time.Since(*obj.LastModified) < time.Hour {
			d.ObjectsToDownload <- obj
		}
	}

	return !lastPage
}
func (d *Downloader) pollObjects() {
	// get new logs every 5 minutes
	ticker := time.NewTicker(5 * time.Minute).C

	s3svc := s3.New(d.Sess, nil)

	// For now, get objects for just today.
	totalPrefix := d.ObjectPrefix(time.Now().UTC())

	// Start the loop to continually ingest access logs.
	for {
		logrus.WithFields(logrus.Fields{
			"prefix": totalPrefix,
			"entity": d.String(),
		}).Info("Getting recent objects")

		processedObjects, err := d.ProcessedObjects()
		if err != nil {
			logrus.Error(err)
		}

		cb := func(bucketResp *s3.ListObjectsOutput, lastPage bool) bool {
			return d.accessLogBucketPageCallback(processedObjects, bucketResp, lastPage)
		}

		if err := s3svc.ListObjectsPages(&s3.ListObjectsInput{
			Bucket: aws.String(d.Bucket()),
			Prefix: aws.String(totalPrefix),
		}, cb); err != nil {
			fmt.Fprintln(os.Stderr, "Error listing/paging bucket objects: ", err)
			os.Exit(1)
		}
		logrus.Info("Pausing until the next set of logs are available")
		<-ticker
	}
}

func (d *Downloader) Download() chan state.DownloadedObject {
	go d.pollObjects()
	go d.downloadObjects()
	return d.DownloadedObjects
}
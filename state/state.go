package state

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

const (
	stateFileFormat = "%s-state.json"

	// Somewhat arbitrary -- usually we see about 50 objects per hour in
	// Honeycomb dogfood data.
	//
	// Important thing is that the length is capped and does not grow
	// indefinitely, old objects will not need de-dupe protection as they
	// will not be returned in the list objects results once an hour has
	// elapsed.
	maxProcessedObjects = 20000
)

// Stater lets us gain insight into the current state of object processing. It
// could be backed by the local filesystem, cloud abstractions such as
// DynamoDB, consistent value stores like etcd, etc.
type Stater interface {
	// ProcessedObjects returns the full list of which objects have been
	// processed already.
	ProcessedObjects() ([]string, error)

	// SetProcessed indicates that downloading, processing, and sending the
	// object to Honeycomb has been completed successfully.
	SetProcessed(object string) error
}

// Used to communicate between the various pieces which are relying on state
// information.
type DownloadedObject struct {
	Object, Filename string
}

// FileStater is an implementation for indicating processing state using the
// local filesystem for backing storage.
type FileStater struct {
	*sync.Mutex
	StateDir string
	Service  string
}

func NewFileStater(stateDir, service string) *FileStater {
	return &FileStater{
		Mutex:    &sync.Mutex{},
		StateDir: stateDir,
		Service:  service,
	}
}

func (f *FileStater) stateFile() string {
	return filepath.Join(f.StateDir, fmt.Sprintf(stateFileFormat, f.Service))
}

func (f *FileStater) processedObjects() ([]string, error) {
	var objs []string

	if _, err := os.Stat(f.stateFile()); os.IsNotExist(err) {
		// make sure file exists first run
		if err := ioutil.WriteFile(f.stateFile(), []byte(`[]`), 0644); err != nil {
			return objs, fmt.Errorf("Error writing file: %s", err)
		}

		return objs, nil
	}

	data, err := ioutil.ReadFile(f.stateFile())
	if err != nil {
		return objs, fmt.Errorf("Error reading object cursor file: %s", err)
	}

	if err := json.Unmarshal(data, &objs); err != nil {
		return objs, fmt.Errorf("Unmarshalling state file JSON failed: %s", err)
	}

	return objs, nil
}

func (f *FileStater) ProcessedObjects() ([]string, error) {
	f.Lock()
	defer f.Unlock()
	return f.processedObjects()
}

func (f *FileStater) SetProcessed(object string) error {
	f.Lock()
	defer f.Unlock()

	processedObjects, err := f.processedObjects()
	if err != nil {
		return err
	}

	processedObjects = append(processedObjects, object)

	if len(processedObjects) > maxProcessedObjects {
		// "rotate" oldest remembered object out so state file
		// does not grow indefinitely
		processedObjects = processedObjects[1:]
	}

	processedData, err := json.Marshal(processedObjects)
	if err != nil {
		return fmt.Errorf("Marshalling JSON failed: %s", err)
	}

	if err := ioutil.WriteFile(f.stateFile(), processedData, 0644); err != nil {
		return fmt.Errorf("Writing file failed: %s", err)
	}

	return nil
}

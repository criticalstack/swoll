package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second
	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second
	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
	// Maximum message size allowed from peer.
	maxMessageSize = 4096
)

// Endpoint is all the information needed to connect and communicate with a
// swoll-server probe.
type Endpoint struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	UseTLS   bool
}

// StreamMessage will pack a TraceEvent along with the originating Endpoint
// so we can correlate where events were sourced.
type StreamMessage struct {
	Ep   *Endpoint         `json:"endpoint"`
	Data *event.TraceEvent `json:"payload"`
}

type traceJob struct {
	ID    string          `json:"id"`
	Trace *v1alpha1.Trace `json:"traceSpec"`
}

// NewEndpoint creates a new endpoint context for creating, reading, and
// modifying jobs.
func NewEndpoint(host string, port int, useTLS bool) *Endpoint {
	return &Endpoint{
		Hostname: host,
		Port:     port,
		UseTLS:   useTLS,
	}
}

// URL generates a properly formatted URL which is used to connect to the given
// endpoint.
func (ep *Endpoint) URL(path string, wsock bool) *url.URL {
	var scheme string

	if wsock {
		if ep.UseTLS {
			scheme = "wss"
		} else {
			scheme = "ws"
		}
	} else {
		if ep.UseTLS {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	return &url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s:%d", ep.Hostname, ep.Port),
		Path:   path,
	}
}

// CreateTrace will attempt to create a job of `spec` format. If the `id` is
// specified, it will use this string to denote the identity of the job and
// not a randomly-generated one.
func (ep *Endpoint) CreateTrace(ctx context.Context, id, ns string, spec *v1alpha1.TraceSpec) (*v1alpha1.Trace, error) {
	jspec, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}

	durl := ep.URL(fmt.Sprintf("/jobs/namespaces/%s", ns), false).String()
	req, err := http.NewRequestWithContext(ctx, "POST", durl, bytes.NewBuffer(jspec))
	if err != nil {
		return nil, err
	}

	// if the id is specified here, append it to the arguments so that
	// the endpoint will use this ID for the job, and not a random one.
	args := req.URL.Query()
	if id != "" {
		args.Add("id", id)
	}

	req.URL.RawQuery = args.Encode()
	req.Header.Set("Content-Type", "application/json")

	// create the client and do the request.
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// read the response from the endpoint
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 201 {
		return nil, fmt.Errorf(resp.Status, string(body))
	}

	job := traceJob{}
	if err = json.Unmarshal(body, &job); err != nil {
		return nil, err
	}

	return job.Trace, nil
}

func (ep *Endpoint) createWebsock(ctx context.Context, url string) (*websocket.Conn, error) {
	dial := websocket.Dialer{}
	conn, _, err := dial.DialContext(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	conn.SetReadLimit(maxMessageSize)

	if err = conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		return nil, err
	}

	conn.SetPingHandler(func(message string) error {
		err := conn.WriteControl(websocket.PongMessage, []byte(message), time.Time{})
		return err
	})

	conn.SetCloseHandler(func(code int, text string) error {
		fmt.Printf("%s: (%d) %s\n", url, code, text)
		return nil
	})

	return conn, nil
}

func (ep *Endpoint) writeWebsock(conn *websocket.Conn, done chan bool) {
	t := time.NewTicker(pingPeriod)
	defer func() {
		t.Stop()
		conn.Close()
	}()

	for {
		select {
		case <-t.C:
			if err := conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				log.Printf("Error setting write deadline: %v", err)
				return
			}

			tn := time.Now()
			message := []byte(fmt.Sprintf("%d", tn.UnixNano()))

			if err := conn.WriteMessage(websocket.PingMessage, message); err != nil {
				log.Printf("Error writing ping message: %v", err)
				return
			}
		case <-done:
			return
		}
	}
}

// readWebsock is a blocking function which reads messages from a websocket.
func (ep *Endpoint) readWebsock(conn *websocket.Conn, ch chan *StreamMessage, done chan bool) error {
	conn.SetPingHandler(func(message string) error {
		select {
		case <-done:
			return conn.Close()
		default:
			err := conn.WriteControl(websocket.PongMessage, []byte(message), time.Time{})
			return err
		}
	})

	//nolint:errcheck
	conn.SetPongHandler(func(message string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			m := websocket.FormatCloseMessage(websocket.CloseNormalClosure, fmt.Sprintf("%v", err))
			if e, ok := err.(*websocket.CloseError); ok {
				if e.Code != websocket.CloseNoStatusReceived {
					m = websocket.FormatCloseMessage(e.Code, e.Text)
				}
			}
			err := conn.WriteMessage(websocket.CloseMessage, m)
			return err
		}

		var ev *event.TraceEvent

		if err = json.Unmarshal(msg, &ev); err != nil {
			continue
		}

		select {
		case ch <- &StreamMessage{ep, ev}:
		case <-done:
			return nil

		}
	}
}

// ReadTraceJob will read events from the output of a job
func (ep *Endpoint) ReadTraceJob(inctx context.Context, id string, ch chan *StreamMessage, done chan bool) error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	conn, err := ep.createWebsock(ctx, ep.URL(fmt.Sprintf("/jobs/%s/ws", id), true).String())
	if err != nil {
		return err
	}
	go ep.writeWebsock(conn, done)
	return ep.readWebsock(conn, ch, done)
}

// DeleteTraceJob will delete the job `id` from the running jobs list
func (ep *Endpoint) DeleteTraceJob(ctx context.Context, id string) error {
	_, cancel := context.WithCancel(ctx)
	defer cancel()

	client := &http.Client{Timeout: time.Duration(0)}
	request, err := http.NewRequest("DELETE", ep.URL(fmt.Sprintf("/jobs/%s", id), false).String(), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("%s", resp.Status)
	}

	return nil
}

// ReadTrace will connect to an already-running job, but allows a user to
// specify which specific parts to view. For example, if a currently-running
// job "app=nginx" matches the NS "syswall", POD "pod-A" and the container "container-B", then
// this can be called ReadTrace(ctx, "syswall", "pod-A", "container-B", ....)
// to obtain a subset of the stream.
func (ep *Endpoint) ReadTrace(inctx context.Context, ns, pod, container string, ch chan *StreamMessage, done chan bool) error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	var uri string

	// boy, it's almost like golang could really use a ternary operator. This is
	// just so crappy looking it makes me want to pull my hair out.
	if ns != "" && pod != "" && container != "" {
		uri = fmt.Sprintf("/trace/namespaces/%s/pods/%s/containers/%s/ws", ns, pod, container)
	} else if ns != "" && pod != "" && container == "" {
		uri = fmt.Sprintf("/trace/namespaces/%s/pods/%s/ws", ns, pod)
	} else if ns != "" && pod == "" && container == "" {
		uri = fmt.Sprintf("/trace/namespaces/%s/ws", ns)
	} else {
		uri = "/trace/ws"
	}

	conn, err := ep.createWebsock(ctx, uri)
	if err != nil {
		return err
	}

	return ep.readWebsock(conn, ch, done)
}

// RunningJobs will return a list of running jobs on the endpoint.
func (ep *Endpoint) RunningJobs() ([]*v1alpha1.Trace, error) {
	running, _, err := ep.getJobs()
	if err != nil {
		return nil, err
	}
	return running, nil
}

// CompletedJobs returns a list of completed jobs on the endpoint
func (ep *Endpoint) CompletedJobs() ([]*v1alpha1.Trace, error) {
	_, completed, err := ep.getJobs()
	if err != nil {
		return nil, err
	}
	return completed, nil
}

// AllJobs returns a list of all running and completed jobs as one big array
func (ep *Endpoint) AllJobs() ([]*v1alpha1.Trace, error) {
	running, completed, err := ep.getJobs()
	if err != nil {
		return nil, err
	}

	ret := []*v1alpha1.Trace{}
	ret = append(ret, running...)
	ret = append(ret, completed...)

	return ret, nil
}

// getJobs returns a list of active and completed jobs
func (ep *Endpoint) getJobs() ([]*v1alpha1.Trace, []*v1alpha1.Trace, error) {
	resp, err := http.Get(ep.URL("/jobs", false).String())
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	running := make([]*v1alpha1.Trace, 0)
	completed := make([]*v1alpha1.Trace, 0)

	jobs := map[string]map[string]traceJob{}

	if err = json.Unmarshal(body, &jobs); err != nil {
		return nil, nil, err
	}

	for _, v := range jobs["running"] {
		running = append(running, v.Trace)
	}

	for _, v := range jobs["completed"] {
		completed = append(completed, v.Trace)
	}

	return running, completed, nil
}

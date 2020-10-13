package alert

import (
	"errors"
	"sync"
)

const (
	// QueueNew ...
	QueueNew = iota
	// QueueUpdateAdd ...
	QueueUpdateAdd
	// QueueUpdateDelete ...
	QueueUpdateDelete
	// QueueDelete ...
	QueueDelete
)

type (
	// AlertCallTable is a map where the key is the syscall, and the value
	// is of the type AlertInfo.
	alertCallTable map[string]*Info
	// alertTable is a map where the key is the alert-source, and the value
	// is of type alertCallTable
	alertTable map[Source]alertCallTable
	// QueueType just defines QueueUnknown/QueueNew etc...
	QueueType int
	// QueueCallback is a function to call for any process/updates
	QueueCallback func(t QueueType, src *Source, nfo *Info)
	// Queue is the abstraction around a queue of alerts.
	Queue struct {
		sync.Mutex
		queue alertTable
	}
)

func (t QueueType) String() string {
	switch t {
	case QueueNew:
		return "new"
	case QueueUpdateAdd:
		return "updateadd"
	case QueueUpdateDelete:
		return "updatedelete"
	case QueueDelete:
		return "delete"
	default:
		return "unknown"
	}
}

// NewAlertQueue creates a new instance of the alert queue.
func NewAlertQueue() (*Queue, error) {
	return &Queue{queue: make(alertTable)}, nil
}

// Push will process, update internal caches and queues, and
// emit callbacks for new entries, updates, and deletes.
func (aq *Queue) Push(alert *Alert, cb QueueCallback) error {
	if aq == nil {
		return errors.New("nil context")
	}

	switch alert.Info.Status {
	case StatusFiring:
		// first check to determine if the source of this alert
		// is already in our queue.
		aq.Lock()
		tbl, ok := aq.queue[alert.Source]

		if !ok {
			// not found, create the table and plop it into the right bucket
			tbl = make(alertCallTable)

			aq.queue[alert.Source] = tbl

			if cb != nil {
				// call the OnNew callback
				cb(QueueNew, &alert.Source, nil)
			}
		}

		// check to see if the syscall defined in this alert is already in
		// our current call table.
		if _, ok = tbl[alert.Info.Syscall]; !ok {
			// the syscall is not currently in our current queue for this
			// alert-source. Create it, and insert it into the tbl bucket.
			info := &alert.Info
			tbl[alert.Info.Syscall] = info

			if cb != nil {
				cb(QueueUpdateAdd, &alert.Source, &alert.Info)
			}

		}
		aq.Unlock()
	case StatusResolved:
		// grab the calltable for this source
		aq.Lock()
		tbl, ok := aq.queue[alert.Source]
		if !ok {
			// no reason to continue as we do not have this
			// in memory.
			aq.Unlock()
			return nil
		}

		// get info section for this
		info, ok := tbl[alert.Info.Syscall]
		if !ok {
			// no reason to continue, this was never in the call table
			aq.Unlock()
			return nil
		}

		// status change, send an update msg.
		if info.Status != StatusResolved {
			if cb != nil {
				cb(QueueUpdateDelete, &alert.Source, &alert.Info)
			}

		}

		// delete this entry from our table
		delete(tbl, info.Syscall)

		// if the table is emtpy, send a onDelete message and delete
		// it from our queue.
		if len(tbl) == 0 {
			if cb != nil {
				cb(QueueDelete, &alert.Source, nil)
			}

			delete(aq.queue, alert.Source)
		}
		aq.Unlock()
	}

	return nil
}

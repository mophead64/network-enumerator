package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"network-enumerator/internal/model"
)

// Hub fans out events to every connected Server-Sent Events client. This is
// what makes the web UI update live as the scanner discovers new hosts,
// ports, or changes, without polling.
type Hub struct {
	mu      sync.Mutex
	clients map[chan model.Event]struct{}
}

func NewHub() *Hub {
	return &Hub{clients: make(map[chan model.Event]struct{})}
}

func (h *Hub) Broadcast(ev model.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- ev:
		default: // slow client; drop rather than block the scanner
		}
	}
}

func (h *Hub) subscribe() chan model.Event {
	ch := make(chan model.Event, 32)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) unsubscribe(ch chan model.Event) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ch := h.subscribe()
	defer h.unsubscribe(ch)

	fmt.Fprintf(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, b)
			flusher.Flush()
		}
	}
}

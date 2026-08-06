package store

import (
	"time"

	"network-enumerator/internal/model"
)

func (s *Store) AddEvent(evType, message string, entityID int64) (model.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO events (type, message, entity_id, timestamp) VALUES (?, ?, ?, ?)`,
		evType, message, entityID, now)
	if err != nil {
		return model.Event{}, err
	}
	id, err := res.LastInsertId()
	return model.Event{ID: id, Type: evType, Message: message, EntityID: entityID, Timestamp: now}, err
}

func (s *Store) ListEvents(limit int) ([]model.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id, type, message, entity_id, timestamp FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Event{}
	for rows.Next() {
		var e model.Event
		if err := rows.Scan(&e.ID, &e.Type, &e.Message, &e.EntityID, &e.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

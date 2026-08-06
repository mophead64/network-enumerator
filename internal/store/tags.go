package store

import (
	"network-enumerator/internal/model"
)

func (s *Store) ListTags() ([]model.Tag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, name, color FROM tags ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Tag{}
	for rows.Next() {
		var t model.Tag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) CreateTag(name, color string) (model.Tag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if color == "" {
		color = "#6b7280"
	}
	res, err := s.db.Exec(`INSERT INTO tags (name, color) VALUES (?, ?)`, name, color)
	if err != nil {
		return model.Tag{}, err
	}
	id, err := res.LastInsertId()
	return model.Tag{ID: id, Name: name, Color: color}, err
}

func (s *Store) DeleteTag(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM tags WHERE id = ?`, id)
	return err
}

func (s *Store) AddHostTag(hostID, tagID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT OR IGNORE INTO host_tags (host_id, tag_id) VALUES (?, ?)`, hostID, tagID)
	return err
}

func (s *Store) RemoveHostTag(hostID, tagID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM host_tags WHERE host_id = ? AND tag_id = ?`, hostID, tagID)
	return err
}

func (s *Store) tagsForHost(hostID int64) ([]model.Tag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT t.id, t.name, t.color FROM tags t
		JOIN host_tags ht ON ht.tag_id = t.id WHERE ht.host_id = ? ORDER BY t.name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Tag{}
	for rows.Next() {
		var t model.Tag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

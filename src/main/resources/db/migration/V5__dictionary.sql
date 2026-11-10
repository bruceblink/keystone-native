CREATE TABLE IF NOT EXISTS sys_dict_type (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sys_dict_item (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  type_id BIGINT NOT NULL,
  item_value VARCHAR(128) NOT NULL,
  item_label VARCHAR(128) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT fk_dict_item_type FOREIGN KEY (type_id) REFERENCES sys_dict_type(id) ON DELETE CASCADE,
  CONSTRAINT uq_dict_item_value UNIQUE (type_id, item_value)
);
CREATE INDEX idx_dict_item_type_sort ON sys_dict_item(type_id, sort_order, id);

CREATE DATABASE IF NOT EXISTS moustass_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE moustass_db;

CREATE TABLE IF NOT EXISTS users (
  idusers INT NOT NULL AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  role VARCHAR(45) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  is_first_password TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (idusers)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS log_file (
  id_log_file INT NOT NULL AUTO_INCREMENT,
  id_user INT NOT NULL,
  log_journal DATETIME NOT NULL,
  user_public_key VARCHAR(2000) NOT NULL,
  user_file_hash VARCHAR(2000) NOT NULL,
  signed_filed_hash VARCHAR(2000) NOT NULL,
  PRIMARY KEY (id_log_file),
  INDEX id_user_idx (id_user),
  CONSTRAINT fk_log_file_user FOREIGN KEY (id_user)
    REFERENCES users (idusers)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS log_auth (
  id_log_auth INT NOT NULL AUTO_INCREMENT,
  iduser INT NOT NULL,
  log_date DATE NOT NULL,
  log_time DATETIME NOT NULL,
  auth_attempt INT NULL,
  PRIMARY KEY (id_log_auth),
  INDEX iduser_idx (iduser),
  CONSTRAINT fk_log_auth_user FOREIGN KEY (iduser)
    REFERENCES users (idusers)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

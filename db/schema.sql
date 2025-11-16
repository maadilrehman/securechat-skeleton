-- db/schema.sql
CREATE DATABASE IF NOT EXISTS securechat_db CHARACTER SET = 'utf8mb4' COLLATE = 'utf8mb4_unicode_ci';
USE securechat_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(320) NOT NULL,
    username VARCHAR(100) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL, -- hex(SHA256(salt || password))
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

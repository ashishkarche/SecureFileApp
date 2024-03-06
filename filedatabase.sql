CREATE DATABASE filedatabase;

-- Use the newly created database
USE filedatabase;

-- Create a table to store uploaded files
CREATE TABLE uploaded_files (
file_id INT AUTO_INCREMENT PRIMARY KEY,
file_name VARCHAR(255) NOT NULL,
file_data LONGBLOB NOT NULL
);

-- Create a table to store encrypted files
CREATE TABLE encrypted_files (
file_id INT AUTO_INCREMENT PRIMARY KEY,
file_name VARCHAR(255) NOT NULL,
encrypted_data LONGBLOB NOT NULL,
user_id int(11) DEFAULT NULL
);

-- Create a table to store user username & password.

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) DEFAULT NULL,
    username VARCHAR(50) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    password VARCHAR(50) NOT NULL
);

-- Create a table to store encrypted keys.


CREATE TABLE `keys` (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(50) NOT NULL,
    key_data BLOB NOT NULL
);

CREATE TABLE download_links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_id INT NOT NULL,
    user_id INT NOT NULL,
    link_expiry_time TIMESTAMP NOT NULL
);


CREATE TABLE admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

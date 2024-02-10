-- Create the database
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
    encrypted_data LONGBLOB NOT NULL
);

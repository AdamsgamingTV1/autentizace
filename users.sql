CREATE DATABASE user_auth;

USE user_auth;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,     
    username VARCHAR(50) UNIQUE NOT NULL,   
    name VARCHAR(100) NOT NULL,              
    email VARCHAR(100) UNIQUE NOT NULL,      
    password VARCHAR(255) NOT NULL           
);


-- create the database for the ctf challenge
create database if not exists strong_pass_users;

-- switch db to the newly created one
use strong_pass_users;

create table if not exists accounts (
    _id bigint auto_increment primary key,
    username varchar(60) not null unique,
    email varchar(60) not null unique,
    password varchar(255) not null,
    resetPasswordToken varchar(100),
    resetPasswordExpires DATETIME
);
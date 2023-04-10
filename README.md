# CPSC 449 Spring Project

## Description

This project is a RESTful API using Flask that covers error handling, authentication, and file handling. 
The API will have two types of routes - public routes that can be accessed without authentication and 
protected admin routes that require authentication. The purpose of this assignment is to help understand how to
build a robust API that can handle errors, authenticate users, and handle file uploads.

The protected admin routes are defined with @token_required decorator. All other routes are public.

This project in no way demostrates how security should be handled. All things done in public routes like 
exposing usernames and passwords from the database are purely done for testing and educational purposes.

## How to run
Set up Python virtual environment: `py -m venv .venv`

Activate the virtual environment: `.\.venv\Scripts\activate`

Install requirements: `py -m pip install flask` `py -m pip install jwt`

Run Flask: `py -m flask run`

Run in Debug Mode: `py -m flask --debug run`

## Credits
**Author**: Ronald Lee

**Email**: ronaldvlee@csu.fulleton.edu

**Class**: CPSC 449, Web Back-end Engineering

**Instructor**: Harsh Anilbhai Bodgal

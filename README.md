# Web Application Project

## Overview

This project is a backend-focused web application that implements a set of
RESTful APIs for client–server interaction and basic data management.

The goal of this project is to demonstrate practical exposure to web
application architecture, HTTP-based communication, and API design using
Python.

---

## Features

- RESTful API endpoints for handling client requests
- JSON-based request and response format
- Backend logic separated from application startup
- Simple database-backed data management

---

## Project Structure

```bash
Web-Application-Project/
├─ src/
│  ├─ api.py          # Core REST API implementation
│  └─ start_api.py    # Application entry point
├─ requirements.txt
├─ .gitignore
└─ README.md
```

---

## Technologies

- Python
- RESTful APIs
- HTTP / JSON
- SQLite (for lightweight data storage)

---

## How to Run

1. Install dependencies:

   pip install -r requirements.txt

2. Start the API server:

   python src/start_api.py

The service will start locally and expose REST endpoints for client interaction.

---

## Notes

This project focuses on backend development and API design.
Frontend implementation is intentionally minimal.

The repository has been cleaned and refactored from an academic assignment to
present a concise and standalone web application suitable for public
demonstration.

---

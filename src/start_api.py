#!/usr/bin/env python3

import sys
import os
import socket
import time

def find_free_port():
    """Find a free port to use"""
    ports = [5000, 5001, 5002, 8000, 8080, 3000, 3001]
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        if result != 0:  # Port is free
            return port
    return None

def main():
    # Import the API after checking ports
    port = find_free_port()
    if not port:
        print("ERROR: No free ports available!")
        sys.exit(1)
    
    print(f"Starting API on port {port}...")
    
    # Set environment variable for port
    os.environ['API_PORT'] = str(port)
    
    # Import and run the API
    from z5540213_api import app, init_database
    
    # Initialize database
    init_database()
    
    print(f"\n{'='*60}")
    print(f"API Server Starting")
    print(f"{'='*60}")
    print(f"Port: {port}")
    print(f"URL: http://localhost:{port}")
    print(f"Swagger: http://localhost:{port}/swagger")
    print(f"{'='*60}\n")
    
    # Run without debug mode to avoid reload issues
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Direct runner for the Flask API server."""

from app.server import create_app

if __name__ == "__main__":
    app = create_app()
    print("\n" + "="*50)
    print("🚀 TEL252 Secure Chat API Server")
    print("="*50)
    print(f"✓ Server running on: http://127.0.0.1:5000")
    print(f"✓ Health endpoint: http://127.0.0.1:5000/health")
    print(f"✓ Press CTRL+C to quit")
    print("="*50 + "\n")
    
    app.run(host="127.0.0.1", port=5000, debug=False)

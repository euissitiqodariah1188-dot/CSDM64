# CSDM64
you can connect html to html  and html to exe 
this is guide for you (you need cloud root for this)
CSMD64.py Deployment Guide
CSMD64.py is an Enterprise-Grade Bridge System. Due to its binary (.exe) process management and low-level communication, its deployment requires an appropriate environment.

1. Environment Setup
Ensure your server/cloud root has Python 3.8+ installed.

Dependency Installation:
Run this command in your server terminal:

Bash
pip install aiohttp websockets cryptography psutil
(This dependency is required for the HTTP, WebSocket, encryption, and monitoring features to work optimally).

2. Folder Structure (Standardized Structure)
To keep your log files, database, and engine well-organized, use the following structure:

Plaintext
/project_root
│
├── CSMD64.py # Main engine (do not change)
├── main.py # Entry point for your code
├── /config # Save csmd64_config.json here
├── /html_files # Folder for HTML files to be bridged
├── /allowed_exes # Folder for secure .exe files
├── /logs # Automatic folder for system logs
└── /data # Automatic folder for SQLite & encryption keys
3. Initialize Code (main.py)
Create a main.py file as the entry point for your application:

Python
import asyncio
from CSMD64 import CSMD64, CSMD64Config

async def main():
# Setup server configuration
config = CSMD64Config(host="0.0.0.0", port=8765)
csmd = CSMD64(config)

# Run the system
await csmd.start()
print("CSMD64 System is running!")

if __name__ == "__main__":
asyncio.run(main())
4. Cloud Root Selection (The Right Habitat)
Do not use regular web hosting or serverless functions because CSMD64.py requires native process access.

Recommendation: Use a Dedicated VPS (such as Vultr, DigitalOcean, or Hetzner) with CPU optimization.

Operating System: Windows Server is highly recommended if the primary goal is to bridge .exe applications so that Inter-Process Communication (IPC) runs natively without overhead.

Access: Make sure you have full access (Root/Administrator) so that firewall and socket management are not restricted by the hosting system.

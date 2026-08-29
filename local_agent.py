import time
import psutil
import requests
import json
import os

# Configuration
# For local testing, this points to your local Flask development server.
# When you deploy to Vercel, change this to your live Vercel URL.
BACKEND_URL = "http://127.0.0.1:5000/api/analyze"
MONITOR_INTERVAL = 10  # How often the agent scans the system (in seconds)

def gather_system_data():
    """
    Gathers basic system metrics and active processes to send to Sentinel.
    This acts as our Local OS interaction layer.
    """
    try:
        # 1. Gather basic hardware telemetry
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        # 2. Gather the top 3 processes consuming the most memory
        processes = []
        for proc in sorted(psutil.process_iter(['pid', 'name', 'memory_percent']), 
                           key=lambda p: p.info['memory_percent'] or 0, 
                           reverse=True)[:3]:
            # Filter out empty or None process names
            if proc.info['name']:
                processes.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
                
        process_list_str = ", ".join(processes) if processes else "No significant processes detected."
        
        # 3. Format the data into a readable log for the AI
        log_entry = (f"[LOCAL SYSTEM SCAN] CPU Usage: {cpu_percent}%, Memory Usage: {memory.percent}%. "
                     f"Highest memory processes currently active: {process_list_str}.")
        
        return log_entry
    except Exception as e:
        return f"[LOCAL SYSTEM ERROR] Failed to gather system telemetry: {str(e)}"

def run_agent():
    print("==================================================")
    print("[*] Sentinel Local Agent Initialized")
    print(f"[*] Target OS: {os.name}")
    print(f"[*] Monitoring system every {MONITOR_INTERVAL} seconds.")
    print(f"[*] Connected to Intelligence Backend: {BACKEND_URL}")
    print("==================================================\n")
    
    while True:
        log_entry = gather_system_data()
        print(f"[>] Outbound Telemetry: {log_entry}")
        
        # Added 'source' tag to distinguish agent logs from web dashboard simulations
        payload = {"log": log_entry, "source": "agent"}
        
        try:
            # Send the system data to our existing Flask/Groq backend
            response = requests.post(
                BACKEND_URL, 
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload)
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    analysis = data.get('analysis', '')
                    print(f"\n[<] Sentinel AI Threat Analysis:\n{analysis}\n")
                    print("-" * 50)
                else:
                    print(f"[!] Backend Error: {data.get('message')}\n")
            else:
                print(f"[!] Server rejected the payload. HTTP Status: {response.status_code}\n")
                
        except requests.exceptions.ConnectionError:
            print("[!] Connection failed. Is the Flask backend currently running on 127.0.0.1:5000?\n")
            
        time.sleep(MONITOR_INTERVAL)

if __name__ == "__main__":
    run_agent()
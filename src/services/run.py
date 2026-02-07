
import uvicorn
import multiprocessing
import time
import sys
import os

# Ensure src is in path
sys.path.append(os.getcwd())

def run_director():
    uvicorn.run("src.services.director:app", host="127.0.0.1", port=8000, log_level="info")

def run_image_repo():
    uvicorn.run("src.services.image_repo:app", host="127.0.0.1", port=8001, log_level="info")

if __name__ == "__main__":
    p1 = multiprocessing.Process(target=run_director)
    p2 = multiprocessing.Process(target=run_image_repo)
    
    print("Starting SecureEV-OTA Services (Director:8000, ImageRepo:8001)...")
    p1.start()
    p2.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping services...")
        p1.terminate()
        p2.terminate()
        p1.join()
        p2.join()

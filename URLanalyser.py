import os
import requests
import base64
API_KEY =os.getenv("VIRUSTOTAL_API_KEY")

def get_url_id(url):
    encoded_url= base64.urlsafe_b64decode(url.encode()).decode()
    return encoded_url.rstrip("=")

def check_url(url):
    if not API_KEY:
        print("API key not found. please set VIRUSTOTAL_API_KEY in environment variable.")
        return
    print("\nchecking URL:",url)

    url_id = get_url_id(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    try:
        responase = requests.get(api_url, headers=headers)
        if responase.status_code ==200:
            data = responase.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious =stats.get("malicious",0)
            suspicious = stats.get("suspicious",0)
            phishing = stats.get("phishing",0)
            harmless = stats.get("harmless",0)

            print("\n=====URL Report=====")
            print("malicious:", malicious)
            print("suspicious:",suspicious)
            print("phishing:",phishing)
            print("==========================")

            if malicious>0 or phishing >0 or suspicious>0:
                print("\nWarning: This URLmay not be safe.")
            else:
                print("\nlook clean based on current VirusTotal result.")

        elif responase.status_code==404:
            print("This URL is not in VirusTotal's database yet.")
        else:
            print(f"Request failed with status code:{responase.status_code}")

    except requests.exceptions.RequestException as e:
        print("network error :",e)
    except KeyError:
        print("Unexpected response format from VirusTotal.")


if __name__ == "__main__":
    print("=== URL Checker ===")
    user_url = input("Enter URL: ").strip()
    check_url(user_url)   

import requests
import sys

# Hardcoded credentials for testing
TOKEN = "7687532927:AAFb5eLRAFrszRJOpPwIzlZ2P4GoFdU1RxA"
CHAT_ID = "5032403046"

def send_test_message():
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": "🔔 Test Notification from Local Machine 🔔\n\nSi lees esto, el bot funciona correctamente."
    }
    
    try:
        print(f"Sending message to {CHAT_ID}...")
        response = requests.post(url, json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("\n✅ Message sent successfully!")
        else:
            print("\n❌ Failed to send message.")
            
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    send_test_message()

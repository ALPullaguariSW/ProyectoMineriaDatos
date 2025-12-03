import requests
import time

TOKEN = "7687532927:AAFb5eLRAFrszRJOpPwIzlZ2P4GoFdU1RxA"
URL = f"https://api.telegram.org/bot{TOKEN}/getUpdates"

def get_chat_id():
    print(f"1. Busca a tu bot en Telegram: @plataforma_encuentro_bot")
    print(f"2. Envíale un mensaje (ej: 'Hola')")
    print(f"3. Esperando mensaje...")
    
    while True:
        try:
            response = requests.get(URL)
            data = response.json()
            
            if "result" in data and len(data["result"]) > 0:
                # Get the last update
                last_update = data["result"][-1]
                chat_id = last_update["message"]["chat"]["id"]
                user = last_update["message"]["from"]["first_name"]
                
                print(f"\n¡Mensaje recibido de {user}!")
                print(f"✅ TU CHAT ID ES: {chat_id}")
                print("\nCopia este ID y úsalo en tus GitHub Secrets como TELEGRAM_CHAT_ID")
                break
            
            time.sleep(2)
            print(".", end="", flush=True)
            
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(2)

if __name__ == "__main__":
    get_chat_id()

import requests

# 1️⃣ Define the video player token
token = "cf94d3605241b8a3dae9dcb6ccc79373"

# 2️⃣ Send a GET request to the API with the token
response = requests.get(f"https://api.masterapi.tech/get/get-hls-key?token={token}")

# 3️⃣ Check if the request was successful
if response.status_code == 200:
    data = response.json()
    
    # 4️⃣ Extract and print the URLs
    video_url = data.get("Url")
    player_url = data.get("PlayerUrl")
    
    if video_url and player_url:
        print("✅ Video URL:", video_url)
        print("🎥 Player URL:", player_url)
    else:
        print("⚠️ Missing URL data in response.")
else:
    print(f"❌ Error: {response.status_code} - {response.text}")

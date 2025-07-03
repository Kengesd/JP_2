import os
import requests

# Create flags directory if it doesn't exist
os.makedirs('static/images/flags', exist_ok=True)

# Flag image URLs (using flagpedia.net for country flags)
flags = {
    'us': 'https://flagcdn.com/w40/us.png',  # US flag for English
    'th': 'https://flagcdn.com/w40/th.png',  # Thailand flag for Thai
    'jp': 'https://flagcdn.com/w40/jp.png'   # Japan flag for Japanese
}

# Download each flag
for code, url in flags.items():
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(f'static/images/flags/{code}.png', 'wb') as f:
            f.write(response.content)
        print(f'Downloaded {code}.png')
    except Exception as e:
        print(f'Error downloading {code}.png: {e}')

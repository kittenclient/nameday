import asyncio
import json
import requests
from datetime import datetime, timedelta
from re import search
from typing import NamedTuple, Union

# Load configuration from config.json
with open("config.json") as config_file:
    config = json.load(config_file)

# Constants for URLs and intervals
AUTHORIZE = "https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
XBL = "https://user.auth.xboxlive.com/user/authenticate"
XSTS = "https://xsts.auth.xboxlive.com/xsts/authorize"
NAME_CHANGE_URL = "https://api.minecraftservices.com/minecraft/profile/name/"
DISCORD_WEBHOOK_URL = config["discord_webhook_url"]
NAME_CHANGE_INTERVAL = 30  # Interval in seconds for trying name change again
REAUTH_INTERVAL = 12 * 60 * 60  # Interval in seconds for re-authentication (12 hours)

userAgent = "Mozilla/5.0 (XboxReplay; XboxLiveAuth/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
login_with_xbox = "https://api.minecraftservices.com/authentication/login_with_xbox"
ownership = "https://api.minecraftservices.com/entitlements/mcstore"
profile = "https://api.minecraftservices.com/minecraft/profile"

# Notification to Discord Webhook
def discord_notify(message: str, ping_everyone: bool = False):
    """
    Sends a notification to a Discord webhook.
    """
    data = {
        "content": f"@everyone {message}" if ping_everyone else message
    }
    response = requests.post(DISCORD_WEBHOOK_URL, json=data)
    if response.status_code != 204:
        print(f"[{datetime.now()}] Discord notification failed with status code {response.status_code}")

# Helper NamedTuples to handle responses from various API calls
class UserLoginResponse(NamedTuple):
    refresh_token: str
    access_token: str
    expires_in: int
    loggedin: bool = False

class XBLAuthenticateResponse(NamedTuple):
    user_hash: str
    token: str

class XSTSAuthenticateResponse(NamedTuple):
    user_hash: str
    token: str

class UserProfile(NamedTuple):
    username: Union[str, None]
    uuid: Union[str, None]

# XboxLive and Microsoft authentication classes
class Microsoft:
    def __init__(self, client: requests.Session = None) -> None:
        self.client = client if client is not None else requests.Session()

    def xbl_authenticate(self, login_resp: UserLoginResponse) -> XBLAuthenticateResponse:
        """
        Authenticate using Xbox Live credentials.
        """
        headers = {"User-Agent": userAgent, "Accept": "application/json", "x-xbl-contract-version": "0"}
        payload = {"RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT", "Properties": {
            "AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": login_resp.access_token}}
        resp = self.client.post(XBL, json=payload, headers=headers)
        if resp.status_code != 200:
            raise Exception("XBL Authentication failed")
        data = resp.json()
        return XBLAuthenticateResponse(token=data["Token"], user_hash=data["DisplayClaims"]["xui"][0]["uhs"])

    def xsts_authenticate(self, xbl_resp: XBLAuthenticateResponse) -> XSTSAuthenticateResponse:
        """
        Authenticate with the XSTS token for Minecraft services.
        """
        headers = {"User-Agent": userAgent, "Accept": "application/json", "x-xbl-contract-version": "1"}
        payload = {"RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT", "Properties": {
            "SandboxId": "RETAIL", "UserTokens": [xbl_resp.token]}}
        resp = self.client.post(XSTS, json=payload, headers=headers)
        if resp.status_code != 200:
            raise Exception("XSTS Authentication failed")
        data = resp.json()
        return XSTSAuthenticateResponse(token=data["Token"], user_hash=data["DisplayClaims"]["xui"][0]["uhs"])

    def login_with_xbox(self, token: str, user_hash: str) -> str:
        """
        Login with the Xbox Live token to get the Minecraft access token.
        """
        headers = {"Accept": "application/json", "User-Agent": userAgent}
        payload = {"identityToken": f"XBL3.0 x={user_hash};{token}"}
        resp = self.client.post(login_with_xbox, json=payload, headers=headers)
        if "access_token" not in resp.text:
            raise Exception("LoginWithXbox Authentication failed")
        return resp.json()["access_token"]

    def user_hash_game(self, access_token: str) -> bool:
        """
        Check if the user owns Minecraft.
        """
        headers = {"Accept": "application/json", "User-Agent": userAgent, "Authorization": f"Bearer {access_token}"}
        resp = self.client.get(ownership, headers=headers)
        return len(resp.json()["items"]) > 0

    def get_user_profile(self, access_token: str) -> UserProfile:
        """
        Retrieve the user's Minecraft profile (username and UUID).
        """
        headers = {"Accept": "application/json", "User-Agent": userAgent, "Authorization": f"Bearer {access_token}"}
        resp = self.client.get(profile, headers=headers).json()
        return UserProfile(username=resp.get("name"), uuid=resp.get("id"))

class XboxLive:
    def __init__(self, client: requests.Session = None) -> None:
        self.client = client if client is not None else requests.Session()

    def user_login(self, email: str, password: str) -> UserLoginResponse:
        """
        Perform the login with Xbox credentials (email and password) and return tokens.
        """
        resp = self.client.get(AUTHORIZE, headers={"User-Agent": userAgent}, allow_redirects=True)
        ppft = search(r"value=\"(.*?)\"", search(r"sFTTag:'(.*?)'", resp.text).group(1)).group(1)
        url_post = search(r"urlPost:'(.+?(?=\'))", resp.text).group(1)

        post_data = {
            "login": email,
            "loginfmt": email,
            "passwd": password,
            "PPFT": ppft
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": userAgent}

        resp = self.client.post(url_post, data=post_data, cookies=resp.cookies, headers=headers, allow_redirects=True)

        if "access_token" not in resp.url:
            raise Exception("Failed to authenticate. Invalid credentials or other error.")

        data = dict(item.split('=') for item in resp.url.split('#')[1].split('&'))

        return UserLoginResponse(
            refresh_token=data["refresh_token"],
            access_token=data["access_token"],
            expires_in=int(data["expires_in"]),
            loggedin=True
        )

def login(email: str, password: str) -> Union[dict, str]:
    """
    Login using email and password to get access token and profile info.
    """
    client = requests.Session()
    xbx = XboxLive(client)
    mic = Microsoft(client)
    login_resp = xbx.user_login(email, password)
    xbl = mic.xbl_authenticate(login_resp)
    xsts = mic.xsts_authenticate(xbl)
    access_token = mic.login_with_xbox(xsts.token, xsts.user_hash)
    if mic.user_hash_game(access_token):
        profile = mic.get_user_profile(access_token)
        return {"access_token": access_token, "username": profile.username, "uuid": profile.uuid}
    else:
        return "Not a premium account"

# Updated name change function
async def change_name(name: str, access_token: str):
    """
    Change the Minecraft username to the new name provided.
    """
    url = f"https://api.minecraftservices.com/minecraft/profile/name/{name}"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.put(url, headers=headers)

    if response.status_code == 200:
        discord_notify(f"Name successfully changed to {name}.", ping_everyone=True)
    elif response.status_code == 429:
        discord_notify("Rate limit exceeded. Please wait before trying again.", ping_everyone=False)
    elif response.status_code == 403:
        discord_notify("Failed to change name. Permission denied (possibly already taken or invalid).", ping_everyone=False)
    else:
        discord_notify(f"Failed to change name. Status code: {response.status_code}.", ping_everyone=False)

# Main logic to handle repeated name changes and reauthentication
async def main():
    """
    Main loop for handling the username change and reauthentication.
    """
    email = config["email"]
    password = config["password"]
    new_name = config["new_name"]

    login_data = login(email, password)
    if isinstance(login_data, str):
        discord_notify("Authentication failed. Please check credentials.", ping_everyone=True)
        return

    access_token = login_data["access_token"]
    last_reauth = datetime.now()

    while True:
        await change_name(new_name, access_token)
        await asyncio.sleep(NAME_CHANGE_INTERVAL)  # Wait for the next name change attempt
        if datetime.now() - last_reauth >= timedelta(hours=12):  # Reauthenticate after 12 hours
            login_data = login(email, password)
            if isinstance(login_data, str):
                discord_notify("Re-authentication failed. Please check credentials.", ping_everyone=True)
                return
            access_token = login_data["access_token"]
            last_reauth = datetime.now()

if __name__ == "__main__":
    asyncio.run(main())  # Run the main loop

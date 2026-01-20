import httpx
from typing import Dict, Optional
from fastapi import HTTPException, status

class OAuthHandler:
    """Handles OAuth 2.0 handshakes for various providers."""

    PROVIDERS = {
        "google": "https://www.googleapis.com/oauth2/v3/userinfo",
        "github": "https://api.github.com/user"
    }

    @staticmethod
    async def get_user_data(provider: str, token: str) -> Dict:
        """Fetch user data from the provider using the access token."""
        if provider not in OAuthHandler.PROVIDERS:
            raise HTTPException(status_code=400, detail="Unsupported provider")

        url = OAuthHandler.PROVIDERS[provider]
        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Failed to fetch user data from {provider}"
                )
            return response.json()

    @staticmethod
    def parse_google_data(data: Dict) -> Dict:
        return {
            "email": data["email"],
            "name": data.get("name"),
            "picture": data.get("picture"),
            "provider_id": data["sub"]
        }

    @staticmethod
    def parse_github_data(data: Dict) -> Dict:
        return {
            "email": data["email"], # Note: requires 'user:email' scope
            "name": data.get("name"),
            "picture": data.get("avatar_url"),
            "provider_id": str(data["id"])
        }

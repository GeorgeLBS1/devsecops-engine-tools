import requests
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.authentication_method import (
    AuthenticationGateway
)

class GenericOauth(AuthenticationGateway):
    def __init__(self, data, endpoint):
        self.data: dict = data
        self.endpoint = endpoint
        self.config = {}

    def process_data(self):

        self.config = {
            "method": self.data["security_auth"].get("method", "POST"),
            "path": self.data["security_auth"]["path"],
            "grant_type": self.data["security_auth"]["grant_type"],
            "scope": self.data["security_auth"].get("scope", None),
            "headers": self.data["security_auth"]["headers"],
            "client_secret": self.data["security_auth"]["client_secret"],
            "client_id": self.data["security_auth"]["client_id"]
        }
        return self.config

    def get_access_token(self):
        auth_config = self.process_data()

        if auth_config["grant_type"].lower() "client_credentials":
            return self.get_access_token_resource_owner()
        else:
            raise ValueError("OAuth: Grant type is not supported yet")

    def get_credentials(self):
        return self.get_access_token()

    def get_access_token_client_credentials(self):
        """Obtain access token using client credentials flow."""
        try:
            required_keys = ["client_id", "client_secret"]
            if not all(key in self.config for key in required_keys):
                raise ValueError("One or more keys is missing in OAuth config")

            data = {
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
                "grant_type": "client_credentials",
                "scope": self.config["scope"],
            }

            url = self.endpoint + self.config["path"]
            headers = self.config["headers"]
            response = requests.request(
                self.config["method"], url, headers=headers, data=data, timeout=5
            )
            if 200 <= response.status_code < 300:
                result = response.json()["access_token"]
                return (,f"Bearer {result}")
            else:
                print(
                    "OAuth: Can't obtain access token"
                    "token Unknown status "
                    "code {0}: -> {1}".format(response.status_code, response.text)
                )
        except (ConnectionError, ValueError, KeyError) as e:
            print("OAuth: Can't obtain access token: {0}".format(e))
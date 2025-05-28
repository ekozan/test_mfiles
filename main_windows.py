import uuid
import urllib.parse
import requests
from requests.cookies import RequestsCookieJar
import tkinter as tk
from tkinter import messagebox, ttk
from mfiles_structs import *

class PluginInfoConfiguration:
    def __init__(self, data):
        self.data = data
        self.Configuration = data.get('Configuration', {})
        self.VaultGuid = data.get('VaultGuid')
        
    def IsOAuthPlugin(self):
        # À adapter selon les attributs réels de l’API
        return self.data.get('IsOAuth', False)
    
    def GenerateAuthorizationUri(self, state: str) -> str:
        return self.Configuration.get("AuthorizationUri", "") + f"?state={state}"
    
    def GetAppropriateRedirectUri(self) -> str:
        return self.Configuration.get("RedirectUri", "")
    
    def GetTokenEndpoint(self) -> str:
        return self.Configuration.get("TokenEndpoint", "")
    
    def GetClientID(self) -> str:
        return self.Configuration.get("ClientId", "")
    
    def GetClientSecret(self) -> str:
        return self.Configuration.get("ClientSecret", "")
    
    def GetResource(self) -> str:
        return self.Configuration.get("Resource", "")
    
    def GetScope(self) -> str:
        return self.Configuration.get("Scope", "")
    
    def GetSiteRealm(self) -> str:
        return self.Configuration.get("SiteRealm", "")

class OAuth2TokenResponse:
    def __init__(self, data):
        self.AccessToken = data.get('access_token')
        self.IdToken = data.get('id_token')
        self.TokenType = data.get('token_type')

def get_query_params_dict(uri: str) -> dict:
    parsed = urllib.parse.urlparse(uri)
    return dict(urllib.parse.parse_qsl(parsed.query))

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("REST API Vault Connector")
        self.client = None
        self.oAuthPluginInfo = None
        self.connectionDetails = type("ConnectionDetails", (), {})()
        self.connectionDetails.NetworkAddress = ""
        
        # UI Components
        self.webBrowser = tk.Label(self, text="WebBrowser Placeholder")
        self.webBrowser.pack()
        self.vaultContents = ttk.Treeview(self)
        self.vaultContents.pack()
        self.connect_button = tk.Button(self, text="Connect", command=self.Connect_Click)
        self.connect_button.pack()
        self.vaultContents.bind("<<TreeviewOpen>>", self.TreeViewItem_Expanded)
        
    def Connect_Click(self):
        self.webBrowser.pack_forget()
        self.vaultContents.pack_forget()
        for i in self.vaultContents.get_children():
            self.vaultContents.delete(i)
        try:
            baseUri = self.connectionDetails.NetworkAddress
            parsed_uri = urllib.parse.urlparse(baseUri)
            if not parsed_uri.scheme or not parsed_uri.netloc:
                messagebox.showerror("Error", f"Cannot parse {baseUri} as a valid network address.")
                return
            self.client = requests.Session()
            self.client.cookies = RequestsCookieJar()
            base_url = f"{parsed_uri.scheme}://{parsed_uri.netloc}"
            url = f"{base_url}/REST/server/authenticationprotocols.aspx"
            response = self.client.get(url)
            pluginInfoCollection = [PluginInfoConfiguration(d) for d in response.json()]
            for c in response.cookies:
                self.client.cookies.set_cookie(c)
            if not pluginInfoCollection:
                messagebox.showerror("Error", "No authentication plugins configured")
                return
            self.oAuthPluginInfo = next((info for info in pluginInfoCollection if info.IsOAuthPlugin()), None)
            if self.oAuthPluginInfo is None:
                messagebox.showerror("Error", "OAuth is not configured on the vault/server.")
                return
            state = "{" + str(uuid.uuid4()) + "}"
            self.oAuthPluginInfo.Configuration["state"] = state
            auth_url = self.oAuthPluginInfo.GenerateAuthorizationUri(state)
            self.webBrowser.config(text=f"Navigate to: {auth_url}")
            self.webBrowser.pack()
        except Exception as ex:
            messagebox.showerror("Exception", f"Exception obtaining authentication plugin data: {ex}")
    
    async def webBrowser_Navigating(self, uri: str):
        if self.oAuthPluginInfo is None:
            return
        if not uri.startswith(self.oAuthPluginInfo.GetAppropriateRedirectUri()):
            return
        self.webBrowser.pack_forget()
        tokens = await self.ProcessRedirectUri(uri)
        token = tokens.AccessToken
        if self.oAuthPluginInfo.Configuration.get("UseIdTokenAsAccessToken", "false").lower() == "true":
            token = tokens.IdToken
        self.client.headers.update({
            "Authorization": f"Bearer {token}",
            "X-Vault": self.oAuthPluginInfo.VaultGuid
        })
        self.vaultContents.pack()
        self.vaultContents.insert('', 'end', 'root', text="Vault contents")
        self.ExpandTreeViewItem('root')
    
    def ExpandTreeViewItem(self, parent_id, folder=None):
        folder = folder or ""
        for i in self.vaultContents.get_children(parent_id):
            self.vaultContents.delete(i)
        def _populate():
            if not folder.endswith("/"):
                folder += "/"
            url = f"/REST/views{folder}items"
            response = self.client.get(url)
            items = FolderContentItems(response.json()).Items
            for item in items:
                # Logique de peuplement à adapter pour l’UI
                pass
        self.after(0, _populate)

    def TreeViewItem_Expanded(self, event):
        selected_item = self.vaultContents.focus()
        tag = self.vaultContents.item(selected_item, 'text')
        self.ExpandTreeViewItem(selected_item, tag)
    
    async def ProcessRedirectUri(self, redirect_uri: str) -> OAuth2TokenResponse:
        queryParams = get_query_params_dict(redirect_uri)
        if "error" in queryParams:
            raise Exception(f"Exception {queryParams['error']} returned by authorisation endpoint.")
        if self.oAuthPluginInfo.Configuration.get("state") != queryParams.get("state"):
            raise Exception("The state returned by the authorisation endpoint was not correct.")
        code = queryParams.get("code")
        token_endpoint = self.oAuthPluginInfo.GetTokenEndpoint()
        data = {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.oAuthPluginInfo.GetAppropriateRedirectUri(),
            "client_id": (self.oAuthPluginInfo.GetClientID() if not self.oAuthPluginInfo.GetSiteRealm()
                          else f"{self.oAuthPluginInfo.GetClientID()}@{self.oAuthPluginInfo.GetSiteRealm()}")
        }
        resource = self.oAuthPluginInfo.GetResource()
        if resource:
            data["resource"] = resource
        scope = self.oAuthPluginInfo.GetScope()
        if scope:
            data["scope"] = scope
        client_secret = self.oAuthPluginInfo.GetClientSecret()
        if client_secret:
            data["client_secret"] = client_secret
        response = requests.post(token_endpoint, data=data)
        response_json = response.json()
        if not response_json.get("access_token"):
            raise Exception("OAuth token not received from endpoint. Response: " + response.text)
        if response_json.get("token_type") != "Bearer":
            raise Exception("Token type was not bearer. Response: " + response.text)
        return OAuth2TokenResponse(response_json)

# Pour lancer l’application :
# win = MainWindow()
# win.mainloop()

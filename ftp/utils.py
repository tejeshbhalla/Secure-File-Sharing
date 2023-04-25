import os 
from  Varency.settings import client_id,client_secret
import json
from oauth2client.client import  OAuth2WebServerFlow
import requests
from urllib.parse import urlencode
from Varency.settings import CLIENT_SECRET_GOOGLE_DRIVE,TOKEN_URL_GOOGLE_DRIVE,TOKEN_URL,CLIENT_ID,CLIENT_SECRET,OAUTH_SCOPE,REDIRECT_URI,SCOPES_ONEDRIVE,CLIENT_ID_ONEDRIVE,REDIRECT_URI_ONEDRIVE
from django.contrib.sites.shortcuts import get_current_site




def get_authorize_url(request,name,username):
    flow = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, OAUTH_SCOPE, redirect_uri=REDIRECT_URI,access_type='offline'
                               ,state=name+'_'+username)
    authorize_url = flow.step1_get_authorize_url()
    return authorize_url

def get_authorize_url_onedrive(request,name,username):
    domain = get_current_site(request)
    REDIRECT_URI=REDIRECT_URI_ONEDRIVE

    params = {
        'client_id': CLIENT_ID_ONEDRIVE,
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPES_ONEDRIVE,
        'response_type': 'code',
        'access_type': 'offline',
        'state':name+'_'+username,
        'client_secret':CLIENT_SECRET,
    }
    
    oauth_url = f'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{urlencode(params)}'

    return oauth_url










def check_and_refresh_token_onedrive(request,access_token, refresh_token):
    changed=False
    #domain = get_current_site(request)
    #REDIRECT_URI=REDIRECT_URI_ONEDRIVE
    # Define the API endpoint to check if the token has expired
    endpoint = "https://graph.microsoft.com/v1.0/me"

    # Set the authorization header with the access token
    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Make a GET request to the endpoint to check if the token is still valid
    response = requests.get(endpoint, headers=headers)

    # If the token has expired (HTTP status code 401), refresh the token
    if response.status_code == 401:
        changed=True
        # Define the API endpoint for refreshing the token
        endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        headers = {
        "Content-Type": "application/x-www-form-urlencoded"
         }


        # Define the data to include in the POST request to refresh the token
        data = {
            "client_id": CLIENT_ID_ONEDRIVE,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "client_secret": CLIENT_SECRET,
        }

        # Make a POST request to the endpoint to refresh the token
        response = requests.post(endpoint, data=data,headers=headers)

        # If the token was successfully refreshed, update the access token
        if response.status_code == 200:
            access_token = response.json()["access_token"]

            return response.text,changed

    return None,changed
    




def get_access_token_from_code(request,code):
    domain = get_current_site(request)
    REDIRECT_URI=REDIRECT_URI_ONEDRIVE
    data = {
    "grant_type": "authorization_code",
    "code": code,
    "client_id": CLIENT_ID_ONEDRIVE,
    "redirect_uri": REDIRECT_URI,
    'client_secret':CLIENT_SECRET,
    }
    # Make the token request
    response = requests.post(TOKEN_URL, data=data)
    return response.text


def get_access_token_from_code_googledrive(request,code):
    domain = get_current_site(request)
    REDIRECT_URI_=REDIRECT_URI
    data = {
    "grant_type": "authorization_code",
    "code": code,
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI_,
    'client_secret':CLIENT_SECRET_GOOGLE_DRIVE,
    }
    # Make the token request
    response = requests.post(TOKEN_URL_GOOGLE_DRIVE, data=data)
    return response.text








def refreshToken(client_id, client_secret, refresh_token):
        params = {
                "grant_type": "refresh_token",
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token
        }

        authorization_url = "https://oauth2.googleapis.com/token"

        r = requests.post(authorization_url, data=params)

        if r.ok:
                return r.text
        else:
                return None


def verify_token(token):
    url=f'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={token}'
    r=requests.get(url)



def check_and_refresh_googledrive(request, access_token, refresh_token):
    changed = False
    
    # Define the API endpoint to check if the token has expired
    endpoint = 'https://www.googleapis.com/drive/v3/about'

    # Set the authorization header with the access token
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Make a GET request to the endpoint to check if the token is still valid
    response = requests.get(endpoint, headers=headers)

    # If the token has expired (HTTP status code 401), refresh the token
    if response.status_code == 401:
        changed = True

        # Define the API endpoint for refreshing the token
        endpoint = 'https://oauth2.googleapis.com/token'

        # Define the data to include in the POST request to refresh the token
        data = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET_GOOGLE_DRIVE,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        print(refresh_token)
        # Make a POST request to the endpoint to refresh the token
        response = requests.post(endpoint, data=data)
        print(response.text)

        # If the token was successfully refreshed, update the access token
        if response.status_code == 200:
            access_token = response.text

    return access_token, changed





def get_user_email(access_token):
    url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"alt": "json"}

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        return data.get("email")
    else:
        raise Exception(f"Error: {response.text}")
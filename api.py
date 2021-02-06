#!/usr/bin/python3
import requests
import time
import logging
import socket
import json
import logging
from types import SimpleNamespace
import urllib3
urllib3.disable_warnings()


HTTP_TIMEOUT = 30


class HTTPClient():
    """ HTTP Client provides methods to handle communication with HTTP server """

    def http_request(self, method: str, path: str, session: requests = requests, **kwargs) -> requests.Response:
        """ Requests HTTP resource
        :param str method: method that should be issued e.g. GET, POST
        :param str path: path to the resource that should be requested
        :param requests session: session manager that should be used
        :param kwargs: kwargs passed to request method
        :return Response: Response object
        """
        url = "{}{}".format(self.apiUrlProvider, path)
        kwargs.setdefault("timeout", HTTP_TIMEOUT)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", False)
        try:
            return getattr(session, method.lower())(url, **kwargs)
        except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
            logging.error("Invalid URL format: {}".format(url))
        except requests.exceptions.ConnectionError:
            logging.error("Connection error: {}".format(url))
        except requests.RequestException as error:
            logging.error(error)
        except socket.error as err:
            logging.error(err)
        except KeyboardInterrupt:
            logging.error("Module has been stopped")
        return None


class OAuth():
    CI_PARAM = [121, 111, 117, 108, 97, 46, 97, 110, 100]
    CS_PARAM = [113, 78, 90, 84, 70, 50, 51, 68, 119, 86, 110, 119]

    @staticmethod
    def getFormBodyBuilder() -> dict:
        client_id = bytes(OAuth.CI_PARAM).decode()
        client_secret = bytes(OAuth.CS_PARAM).decode()
        return {'client_id': client_id, 'client_secret': client_secret}


class YoulaApi(HTTPClient):
    def __init__(self, device_id='', token=''):
        self.device_id = device_id
        self.token = token
        self.header = {
            'User-Agent': 'Youla/3.22.1 (01bc5cf95) (Android Version 6.0.1)',
            'X-Auth-Token': self.token,
            'X-Youla-Splits': '8a=1|8b=3|8c=1|8m=2|16a=0|16b=0|64a=6|64b=0|100d=10',
            'Content-Type': 'application/json; charset=utf-8',
        }
        self.apiUrlProvider = 'https://api.youla.io/api/v1/'
        self.params = {
            # 'adv_id': '',
            'app_id': 'android/626',
            'uid': self.device_id,
            # 'usr_latitude': '0.0',
            # 'usr_longitude': '0.0',
            'timestamp': int(time.time())
        }

    # PhoneAuthApi
    def auth(self, phone, sms_code):
        data = {'phone': phone, 'code': sms_code, 'uid': self.device_id}
        response = self.http_request(
            method="POST",
            path="auth/confirm",
            headers=self.header,
            params=self.params,
            data=json.dumps(data)
        )
        logging.debug(response.json())
        if response.json().get('data').get('token'):
            self.token = response.json().get('data').get('token')
            self.header['X-Auth-Token'] = self.token
        return response.json()

    def confirmPhone(self, phone, sms_code):
        data = {'phone': phone, 'code': sms_code}
        response = self.http_request(
            method="POST",
            path="auth/phone/verify/confirm",
            headers=self.header,
            params=self.params,
            data=json.dumps(data)
        )
        logging.debug(response.json())
        return response.json()

    def verifyConfirmPhone(self, session_id, phone):
        data = {'token': self.token, 'session_id': session_id, 'uid': self.device_id, 'phone': phone}
        response = self.http_request(
            method="POST",
            path="auth/phone/verify/validate",
            headers=self.header,
            params=self.params,
            data=json.dumps(data)
        )
        logging.debug(response.json())
        return response.json()

    def postPhoneVerifyApprove(self, approve: bool, phone: str):
        data = {'phone': phone, 'approve': str(approve).lower()}
        response = self.http_request(
            method="POST",
            path="auth/phone/verify/approve",
            headers=self.header,
            params=self.params,
            data=json.dumps(data)
        )
        logging.debug(response.json())
        return response.json()

    def authByLibVerify(self, session_id, phone):
        data = {'token': self.token, 'session_id': session_id, 'uid': self.device_id, 'phone': phone}
        response = self.http_request(
            method="POST",
            path="auth/validate",
            headers=self.header,
            params=self.params,
            data=json.dumps(data)
        )
        logging.debug(response.json())
        return response.json()

    # BonusApi
    def getDailyBonuses(self):
        response = self.http_request(
            method="POST",
            path="bonus/daily/apply",
            headers=self.header,
            params=self.params
        )
        logging.debug(response.json())
        return response.json()

    def getRewardedVideoBonuses(self):
        response = self.http_request(
            method="PUT",
            path="bonus/rewarded_video/apply",
            headers=self.header,
            params=self.params
        )
        logging.debug(response.json())
        return response.json()

    # PhoneConfirmationApi
    def startPhoneConfirmation(self, phone):
        data = {'phone': phone, 'uid': self.device_id}
        response = self.http_request(
            method="POST",
            path="auth/phone",
            headers=self.header,
            # params=self.params,
            data=json.dumps(data)
        )
        logging.debug(response.json())
        return response.json()

    def startPhoneConfirmationWithVerify(self, phone):
        '''
        Change phone number
        '''
        data = {'phone': phone, 'uid': 'null'}
        response = self.http_request(
            method="POST",
            path="auth/phone/verify",
            headers=self.header,
            params=self.params,
            data=json.dumps(data)
        )
        logging.debug(response.json())
        return response.json()

    # ShortUrlApi
    def getFilter(self, link_id):
        response = self.http_request(
            method="GET",
            path="short_urls/{}".format(link_id),
            headers=self.header,
            params=self.params
        )
        logging.debug(response.json())
        return response.json()

    # MiscApi
    def getMainBrand(self):
        response = self.http_request(
            method="GET",
            path="splash_screen/main_brand",
            headers=self.header,
            params=self.params
        )
        logging.debug(response.json())
        return response.json()

    # OAuthApi
    def getJwt(self, user_id):
        data = OAuth.getFormBodyBuilder()
        data['grant_type'] = 'password'
        data['username'] = 'youla_{}'.format(user_id)
        data['password'] = self.token
        response = self.http_request(
            method="POST",
            path="oauth/access_token",
            headers=self.header,
            params=self.params,
            data=json.dumps(data),
        )
        logging.debug(response.json())
        return response.json()

    def refreshJwt(self, refresh_token):
        data = OAuth.getFormBodyBuilder()
        data['grant_type'] = 'refresh_token'
        data['refresh_token'] = refresh_token
        response = self.http_request(
            method="POST",
            path="oauth/access_token",
            headers=self.header,
            params=self.params,
            data=json.dumps(data),
        )
        logging.debug(response.json())
        return response.json()

    # UserApi
    def loadUser(self, user_id: str):
        response = self.http_request(
            method="GET",
            path="user/{}".format(user_id),
            headers=self.header,
        )
        logging.debug(response.json())
        return response.json()

    def updateUser(self, user_id: str, body: dict):
        response = self.http_request(
            method="PUT",
            path="user/{}".format(user_id),
            headers=self.header,
            data=json.dumps(body),
        )
        logging.debug(response.json())
        return response.json()

    # CountersApi
    def getCounters(self, user_id: str) -> dict:
        response = self.http_request(
            method="GET",
            path="counters/{}".format(user_id),
            headers=self.header,
        )
        return response.json()


def login_by_phone(self):
    self.startPhoneConfirmation()
    resp = self.auth()
    LocalUser = json.loads(resp.text, object_hook=lambda d: SimpleNamespace(**d))
    return LocalUser

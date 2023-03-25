from pydantic import BaseModel

BSSID_REGEX = "[0-9a-fA-F]{2}"

class WiapiResponse(BaseModel):
    success: bool=True
    data: dict={ 'message': 'OK' }

class WiapiCredentials(BaseModel):
    username: str
    password: str
    admin: bool=False

class WiapiInterface(BaseModel):
    interface: str
    active: bool=True

class WiapiDeauth(BaseModel):
    interface: str
    bssid: str
    packets: int=200
    delay: int=200

from pydantic import BaseModel

class EmailInput(BaseModel):
    subject: str = ""
    sender: str = ""
    header: str = ""
    body: str

class LoginInput(BaseModel):
    email: str
    password: str

class OTPVerifyInput(BaseModel):
    email: str
    otp: str

class URLInput(BaseModel):
    url: str
from pydantic import BaseModel

class Url(BaseModel):
    user_url: str
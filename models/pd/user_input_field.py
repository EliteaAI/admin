try:
    from pydantic.v1 import BaseModel, EmailStr
except:  # pylint: disable=W0702
    from pydantic import BaseModel, EmailStr


class UserInputFieldPD(BaseModel):
    user_email: EmailStr

try:
    from pydantic.v1 import BaseModel
except:  # pylint: disable=W0702
    from pydantic import BaseModel


class RoleDetailModel(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True

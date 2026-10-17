from pydantic import BaseModel, Field

class FileMetadataRequest(BaseModel):
    filename:str=Field(min_length=1)
    content_type:str=Field(min_length=1)

from fastapi import APIRouter
from backend.api.schemas.file import FileMetadataRequest

router = APIRouter()


@router.post("/files/metadata")
def create_file_metadata(file: FileMetadataRequest):
    return {
        "filename": file.filename,
        "content_type": file.content_type
    }

from fastapi import APIRouter, HTTPException, status

from backend.api.schemas.file import FileMetadataRequest
from backend.database.file_repository import save_file_metadata

router = APIRouter()


@router.post("/files", status_code=status.HTTP_201_CREATED)
def create_file(file: FileMetadataRequest):

    file_id = save_file_metadata(
        file.filename,
        file.content_type
    )

    if file_id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save file metadata."
        )

    return {
        "id": file_id,
        "filename": file.filename,
        "content_type": file.content_type
    }

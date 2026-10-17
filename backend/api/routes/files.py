from fastapi import APIRouter, UploadFile, HTTPException, status

from backend.api.schemas.file import FileMetadataRequest
from backend.database.file_repository import save_file_metadata

router = APIRouter()

# Maximum Upload size =10MiB
MAX_FILE_SIZE = 10*1024*1024

# PDF file signature
PDF_SIGNATURE = b"%PDF-"


@router.post("/files", status_code=status.HTTP_201_CREATED)
def create_file(file: FileMetadataRequest):
    """Store the file metadeta in the database"""

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
        "message": "File metadata saved successfully",
        "file_id": file_id
    }


@router.post("/files/upload", status_code=status.HTTP_200_OK)
async def upload_file(file: UploadFile):
    """Validate an uploaded PDF without storing it."""

    try:
        # 1. Check the filename.
        if not file.filename or not file.filename.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file was provided."
            )

        # 2. Check the client-provided MIME type.
        if file.content_type != "application/pdf":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only PDF files are allowed."
            )

        total_size = 0
        signature_bytes = b""

        # 3. Read the file in 64 KiB chunks.
        while True:
            chunk = await file.read(64 * 1024)

            if not chunk:
                break

            total_size += len(chunk)

            # 4. Enforce the 10 MiB size limit.
            if total_size > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail="File exceeds the 10 MiB size limit."
                )

            # 5. Collect enough bytes to check the PDF signature.
            if len(signature_bytes) < len(PDF_SIGNATURE):
                needed = len(PDF_SIGNATURE) - len(signature_bytes)
                signature_bytes += chunk[:needed]

        # 6. Reject empty files with a clear message.
        if total_size == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty."
            )

        # 7. Validate the PDF signature.
        if not signature_bytes.startswith(PDF_SIGNATURE):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file does not have a PDF signature."
            )

        # 8. Return information; do not store the file yet.
        return {
            "message": "PDF validated successfully",
            "filename": file.filename,
            "content_type": file.content_type,
            "size_bytes": total_size
        }

    finally:
        await file.close()

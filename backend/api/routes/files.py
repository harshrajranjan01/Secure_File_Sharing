
from fastapi import APIRouter, UploadFile, HTTPException, status

from backend.crypto.file_crypto import encrypt_file_data
from backend.api.schemas.file import FileMetadataRequest
from backend.database.file_repository import save_file_metadata


router = APIRouter()

# Maximum upload size: 10 MiB
MAX_FILE_SIZE = 10 * 1024 * 1024
CHUNK_SIZE = 64 * 1024

# PDF signature
PDF_SIGNATURE = b"%PDF-"

# Requirements for the current AES-256-GCM implementation
KEY_SIZE = 32
NONCE_SIZE = 12
GCM_TAG_SIZE = 16


@router.post("/files", status_code=status.HTTP_201_CREATED)
def create_file(file: FileMetadataRequest):
    """Save file metadata in the database."""

    file_id = save_file_metadata(
        file.filename,
        file.content_type,
    )

    if file_id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save file metadata.",
        )

    return {
        "message": "File metadata saved successfully",
        "file_id": file_id,
    }


@router.post("/files/upload", status_code=status.HTTP_200_OK)
async def upload_file(file: UploadFile):
    """Validate a PDF, encrypt its bytes, and return safe metadata."""

    try:
        # 1. Validate the filename.
        if not file.filename or not file.filename.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file was provided.",
            )

        # 2. Check the client-provided MIME type.
        if file.content_type != "application/pdf":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only PDF files are allowed.",
            )

        total_size = 0
        chunks = []
        signature_bytes = b""

        # 3. Read the upload in 64 KiB chunks.
        while True:
            chunk = await file.read(CHUNK_SIZE)

            if not chunk:
                break

            total_size += len(chunk)

            # 4. Enforce the maximum file size.
            if total_size > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail="File exceeds the 10 MiB size limit.",
                )

            chunks.append(chunk)

            # 5. Collect the first five bytes for signature checking.
            if len(signature_bytes) < len(PDF_SIGNATURE):
                needed = len(PDF_SIGNATURE) - len(signature_bytes)
                signature_bytes += chunk[:needed]

        # 6. Reject empty uploads.
        if total_size == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty.",
            )

        # 7. Check the PDF signature.
        if not signature_bytes.startswith(PDF_SIGNATURE):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file does not have a PDF signature.",
            )

        # 8. Reconstruct the original bytes.
        file_bytes = b"".join(chunks)

        # 9. Encrypt the file.
        encrypted_package = encrypt_file_data(file_bytes)

        # 10. Validate the encryption result's structure.
        if not isinstance(encrypted_package, dict):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File encryption failed.",
            )

        required_fields = {"ciphertext", "nonce", "key"}

        if not required_fields.issubset(encrypted_package):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File encryption produced an invalid result.",
            )

        ciphertext = encrypted_package["ciphertext"]
        nonce = encrypted_package["nonce"]
        key = encrypted_package["key"]

        # 11. Validate the data types.
        if not all(
            isinstance(value, bytes)
            for value in (ciphertext, nonce, key)
        ):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Encryption output must contain bytes.",
            )

        # 12. Validate the AES-256-GCM key length.
        if len(key) != KEY_SIZE:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Encryption produced an invalid key.",
            )

        # 13. Validate the AES-GCM nonce length.
        if len(nonce) != NONCE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Encryption produced an invalid nonce.",
            )

        # 14. Ciphertext must include the 16-byte authentication tag.
        if len(ciphertext) < GCM_TAG_SIZE:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Encryption produced invalid ciphertext.",
            )

        # 15. Return safe metadata only.
        # Do not return the ciphertext, nonce, or raw DEK.
        return {
            "message": "PDF validated and encrypted successfully",
            "filename": file.filename,
            "content_type": file.content_type,
            "size_bytes": total_size,
            "encryption_status": "encrypted",
        }

    finally:
        await file.close()

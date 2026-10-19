
from fastapi import APIRouter, UploadFile, HTTPException, status, Path
from fastapi.responses import Response

from backend.crypto.file_crypto import (
    encrypt_file_data,
    decrypt_file_data
)

from backend.api.schemas.file import FileMetadataRequest

from backend.crypto.key_wrapping import (
    wrap_file_key,
    unwrap_file_key
)

from backend.storage.encrypted_file_storage import (
    store_encrypted_file,
    delete_encrypted_file,
    read_encrypted_file
)

from backend.database.file_repository import (
    save_encrypted_file_metadata,
    get_encrypted_file_metadata,
    delete_file_metadata,
    list_files_metadata
)


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


@router.post("/files/upload", status_code=status.HTTP_201_CREATED)
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

        # wrap the data encryption key(DEK)
        try:
            key_wrapping_result = wrap_file_key(key)

        except HTTPException:
            raise

        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Key wrapping failed.",
            ) from None

        if not isinstance(key_wrapping_result, dict):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Key wrapping produced an invalid result"
            )

        if not {"wrapped_dek", "nonce"}.issubset(key_wrapping_result):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Key wrapping result is missing required field"
            )

        wrapped_dek = key_wrapping_result["wrapped_dek"]
        key_nonce = key_wrapping_result["nonce"]

        if not isinstance(wrapped_dek, bytes) or len(wrapped_dek) != (KEY_SIZE+GCM_TAG_SIZE):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Key wrapping produced an invalid wrapped DEK",
            )

        if not isinstance(key_nonce, bytes) or len(key_nonce) != NONCE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Key wrapping produced an invalid nonce",
            )

        # Store the Encrypted file and obtain its identifier.
        try:
            storage_key = store_encrypted_file(ciphertext)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store encrypted file.",
            ) from None

        if (
            not isinstance(storage_key, str)
            or len(storage_key) != 64
            or any(char not in "0123456789abcdef" for char in storage_key)
        ):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Encrypted file storage produced an invalid identifier.",
            )

        # save encrypted file metadata to MYSQL.
        try:
            file_id = save_encrypted_file_metadata(
                file.filename,
                file.content_type,
                storage_key,
                nonce,
                wrapped_dek,
                key_nonce,
                total_size,
            )
        except HTTPException:
            try:
                delete_encrypted_file(storage_key)
            except Exception:
                pass
            raise

        except Exception:
            try:
                delete_encrypted_file(storage_key)
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save encrypted file metadata.",
            ) from None

        if file_id is None:
            try:
                delete_encrypted_file(storage_key)
            except Exception:
                pass

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save encrypted file metadata.",
            )

        # 15. Return safe metadata only.
        # Do not return the ciphertext, nonce, or raw DEK.
        return {
            "message": "PDF validated and encrypted successfully",
            "file_id": file_id,
            "filename": file.filename,
            "content_type": file.content_type,
            "size_bytes": total_size,
            "encryption_status": "encrypted",
        }

    finally:
        await file.close()


@router.get("/files/{file_id}/download", status_code=status.HTTP_200_OK)
def download_file(file_id: int = Path(ge=1)):
    """Retrieve, decrypt, and download a stored PDF."""

    # 1. Retrieve the file metadata from mysql
    try:
        metadata = get_encrypted_file_metadata(file_id)

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve file metadata",
        ) from None

    if metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found",
        )

    required_fields = (
        "storage_key",
        "file_nonce",
        "wrapped_dek",
        "key_nonce",
    )

    if any(metadata.get(field) is None for field in required_fields):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="File is missing required encryption metadata",
        )

    # Read the Encrypted file from storage
    try:
        ciphertext = read_encrypted_file(metadata["storage_key"])

    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Encrypted file not found in storage",
        ) from None
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve encrypted file",
        )from None

    if not isinstance(ciphertext, bytes):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Encrypted storage returned invalid data",
        )

    # Unwrp the Data Encryption Key(DEK)
    try:
        dek = unwrap_file_key({
            "wrapped_dek": metadata["wrapped_dek"],
            "nonce": metadata["key_nonce"],
        }
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to recover the file encryption key"
        )

    # Decrypt the file using the recovered DEK
    try:
        original_bytes = decrypt_file_data({
            "ciphertext": ciphertext,
            "nonce": metadata["file_nonce"],
            "key": dek,
        })
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt the file.",
        )

    return Response(
        content=original_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="download.pdf"'
        },
    )


@router.delete("/files/{file_id}")
def delete_file(file_id: int = Path(ge=1)):

    metadata = get_encrypted_file_metadata(file_id)

    if metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File Not found",
        )

    delete = delete_file_metadata(file_id)

    if not delete:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to delete file metadata",
        )

    try:
        storage_key = metadata["storage_key"]
        delete_encrypted_file(storage_key)

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File metadata was deleted, but encrypted file cleanup failed."
        )

    return {
        "message": "File deleted successfully.",
        "file_id": file_id,
    }


@router.get("/files")
def get_files() -> list[dict]:
    "return safe metadata for all stored files"

    files = list_files_metadata()

    return [
        {
            "id": file["id"],
            "filename": file["filename"],
            "content_type": file["content_type"],
            "created_at": file["created_at"],
            "size_bytes": file["size_bytes"],
        }
        for file in files
    ]

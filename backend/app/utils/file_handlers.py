import os
import aiofiles
from datetime import datetime
from fastapi import UploadFile
from app.core.config import settings
import uuid

async def save_uploaded_file(file: UploadFile) -> str:
    """Save uploaded file and return file path"""
    
    # Create uploads directory if it doesn't exist
    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)
    
    # Generate unique filename
    file_ext = os.path.splitext(file.filename)[1]
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    file_path = os.path.join(upload_dir, unique_filename)
    
    # Save file
    async with aiofiles.open(file_path, 'wb') as out_file:
        content = await file.read()
        await out_file.write(content)
    
    return file_path

def validate_file_extension(filename: str) -> bool:
    """Validate file extension"""
    return any(filename.endswith(ext) for ext in settings.ALLOWED_EXTENSIONS)

def cleanup_old_files(days_old: int = 7):
    """Clean up old uploaded files"""
    upload_dir = "uploads"
    if os.path.exists(upload_dir):
        for filename in os.listdir(upload_dir):
            file_path = os.path.join(upload_dir, filename)
            if os.path.isfile(file_path):
                file_age = datetime.now().timestamp() - os.path.getmtime(file_path)
                if file_age > days_old * 86400:
                    os.remove(file_path)
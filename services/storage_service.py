from __future__ import annotations

import os
import re
import secrets
import warnings
from pathlib import Path

from flask import current_app
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.datastructures import FileStorage

_ALLOWED_FOLDERS = {"profiles", "businesses", "portfolio"}
_IMAGE_FORMATS = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}
_IMAGE_OPEN_FORMATS = tuple(_IMAGE_FORMATS)
_MANAGED_PATH_RE = re.compile(r"^uploads/(profiles|businesses|portfolio)/[a-f0-9]{32,40}\.(jpg|png|webp)$")


def upload_storage_root(app=None) -> Path:
    target_app = app or current_app
    configured = str(target_app.config.get("UPLOAD_STORAGE_ROOT") or "").strip()
    root = Path(configured) if configured else Path(target_app.root_path) / "uploads"
    return root.expanduser().resolve()


def ensure_storage_ready(app=None, *, writable_probe: bool = False) -> Path:
    root = upload_storage_root(app)
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    for folder in sorted(_ALLOWED_FOLDERS):
        (root / folder).mkdir(parents=True, exist_ok=True, mode=0o750)
    if writable_probe:
        probe = root / f".write-probe-{secrets.token_hex(8)}"
        try:
            fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        finally:
            probe.unlink(missing_ok=True)
    return root


def _folder_root(folder: str) -> Path:
    normalized = re.sub(r"[^a-z0-9_-]", "", (folder or "").lower())
    if normalized not in _ALLOWED_FOLDERS:
        raise ValueError("Upload folder is invalid.")
    root = ensure_storage_ready()
    target = (root / normalized).resolve()
    if root not in target.parents:
        raise ValueError("Upload folder is invalid.")
    return target


def _copy_bounded(file: FileStorage, destination: Path, max_bytes: int) -> int:
    total = 0
    stream = file.stream
    try:
        stream.seek(0)
    except (AttributeError, OSError):
        pass
    with destination.open("xb") as handle:
        os.chmod(destination, 0o640)
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("Image is too large.")
            handle.write(chunk)
        handle.flush()
        os.fsync(handle.fileno())
    return total


def store_image(file: FileStorage | None, folder: str, max_bytes: int | None = None) -> str | None:
    if not file or not file.filename:
        return None

    max_bytes = int(max_bytes or current_app.config.get("UPLOAD_MAX_FILE_BYTES", 3 * 1024 * 1024))
    if max_bytes <= 0:
        raise ValueError("Upload size configuration is invalid.")
    if file.content_length and file.content_length > max_bytes:
        raise ValueError("Image is too large.")

    normalized_folder = re.sub(r"[^a-z0-9_-]", "", (folder or "").lower())
    root = _folder_root(normalized_folder)
    tmp = root / f".upload-{secrets.token_hex(16)}"
    output: Path | None = None
    try:
        size = _copy_bounded(file, tmp, max_bytes)
        if size <= 0:
            raise ValueError("Uploaded file is empty.")

        max_pixels = int(current_app.config.get("UPLOAD_MAX_PIXELS", 20_000_000))
        max_dim = int(current_app.config.get("UPLOAD_MAX_DIMENSION", 6000))
        Image.MAX_IMAGE_PIXELS = max_pixels

        # Restrict Pillow to the three formats the application actually accepts.
        # This avoids invoking parsers for unrelated formats before we can reject
        # them and materially reduces the attack surface of untrusted uploads.
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(tmp, formats=_IMAGE_OPEN_FORMATS) as check:
                fmt = (check.format or "").upper()
                if fmt not in _IMAGE_FORMATS:
                    raise ValueError("Only JPEG, PNG and WebP images are allowed.")
                if check.width <= 0 or check.height <= 0:
                    raise ValueError("Image dimensions are invalid.")
                if check.width > max_dim or check.height > max_dim or check.width * check.height > max_pixels:
                    raise ValueError("Image dimensions are too large.")
                check.verify()

        with Image.open(tmp, formats=_IMAGE_OPEN_FORMATS) as image:
            fmt = (image.format or "").upper()
            filename = f"{secrets.token_hex(20)}{_IMAGE_FORMATS[fmt]}"
            output = root / filename
            if current_app.config.get("UPLOAD_REQUIRE_REENCODE", True):
                image.load()
                image = ImageOps.exif_transpose(image)
                if fmt == "JPEG" and image.mode not in {"RGB", "L"}:
                    image = image.convert("RGB")
                save_args: dict[str, object] = {}
                if fmt == "JPEG":
                    save_args.update(quality=90, optimize=True)
                elif fmt == "PNG":
                    save_args.update(optimize=True)
                elif fmt == "WEBP":
                    save_args.update(quality=90, method=4)
                image.save(output, format=fmt, **save_args)
            else:
                os.replace(tmp, output)
            os.chmod(output, 0o640)
            return f"uploads/{normalized_folder}/{filename}"
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        if output:
            output.unlink(missing_ok=True)
        raise ValueError("Uploaded file is not a valid image.") from exc
    except Exception:
        if output:
            output.unlink(missing_ok=True)
        raise
    finally:
        tmp.unlink(missing_ok=True)


def resolve_managed_upload(path: str) -> Path | None:
    normalized = (path or "").replace("\\", "/").lstrip("/")
    if not _MANAGED_PATH_RE.fullmatch(normalized):
        return None
    relative = normalized.removeprefix("uploads/")
    root = upload_storage_root()
    target = (root / relative).resolve()
    if root not in target.parents:
        return None
    return target


def delete_managed_file(path: str | None) -> None:
    if not path:
        return
    target = resolve_managed_upload(path)
    if target and target.is_file():
        target.unlink(missing_ok=True)

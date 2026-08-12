r"""QR code helpers: render an account for sharing, and best-effort decode.

Two directions:

*Producing* a QR is fully supported and dependency-light -- :func:`render_png`
turns an account into a scannable ``otpauth://`` QR image via **segno** so you
can move a secret to a phone.

*Reading* a QR from a screenshot is genuinely optional.  A real QR decoder is
not a declared dependency of this app, so the primary enrolment path is pasting
the ``otpauth://`` URI directly.  :func:`decode_image` is a guarded, best-effort
convenience: it uses OpenCV (``cv2``) if it happens to be importable, else
``pyzbar`` if present, and otherwise raises a clear :class:`AuthKeeperError`
telling the user to paste the URI instead.  It never hard-crashes the app.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

from . import vault as _vault
from .errors import AuthKeeperError


def provisioning_uri(account):
    """The ``otpauth://`` URI for *account* (delegates to :mod:`vault`)."""
    return _vault.to_uri(account)


def render_png(account_or_uri, out_path, scale=6, border=4):
    """Render an account (or a raw otpauth URI) to a QR PNG at *out_path*.

    Returns *out_path*.  Requires segno (a declared dependency).
    """
    uri = (account_or_uri if isinstance(account_or_uri, str)
           else provisioning_uri(account_or_uri))
    try:
        import segno
    except Exception as exc:  # noqa: BLE001 - should not happen (declared dep)
        raise AuthKeeperError(f"QR rendering needs the 'segno' package ({exc}).") \
            from exc
    try:
        segno.make(uri, error="m").save(out_path, scale=scale, border=border)
    except Exception as exc:  # noqa: BLE001
        raise AuthKeeperError(f"Could not render QR image: {exc}") from exc
    return out_path


def render_data_uri(account_or_uri, scale=6, border=4):
    """Return the QR as a ``data:image/png;base64,...`` string (for the GUI)."""
    uri = (account_or_uri if isinstance(account_or_uri, str)
           else provisioning_uri(account_or_uri))
    try:
        import io

        import segno
        buf = io.BytesIO()
        segno.make(uri, error="m").save(buf, kind="png", scale=scale,
                                        border=border)
        import base64
        return "data:image/png;base64," + base64.b64encode(
            buf.getvalue()).decode("ascii")
    except Exception as exc:  # noqa: BLE001
        raise AuthKeeperError(f"Could not render QR image: {exc}") from exc


def _decode_with_cv2(path):
    try:
        import cv2  # noqa: F401
    except Exception:
        return None
    try:
        import cv2
        img = cv2.imread(path)
        if img is None:
            raise AuthKeeperError("Could not open that image file.")
        data, _points, _straight = cv2.QRCodeDetector().detectAndDecode(img)
        return data or None
    except AuthKeeperError:
        raise
    except Exception:
        return None


def _decode_with_pyzbar(path):
    try:
        from pyzbar import pyzbar
        from PIL import Image
    except Exception:
        return None
    try:
        results = pyzbar.decode(Image.open(path))
        for r in results:
            try:
                return r.data.decode("utf-8")
            except Exception:  # noqa: BLE001
                continue
        return None
    except Exception:
        return None


def decode_image(path):
    """Best-effort: return the ``otpauth://`` URI decoded from a QR image.

    Tries OpenCV then pyzbar (either may be absent).  Raises a clear
    :class:`AuthKeeperError` if no decoder is available or nothing is found --
    the caller should then ask the user to paste the URI instead.
    """
    for decoder in (_decode_with_cv2, _decode_with_pyzbar):
        data = decoder(path)
        if data:
            if not data.lower().startswith("otpauth://"):
                raise AuthKeeperError(
                    "That QR code is not an otpauth:// 2FA code.")
            return data
    raise AuthKeeperError(
        "Could not decode a QR from that image on this system. Open the "
        "otpauth:// URI and paste it instead (image decoding needs OpenCV or "
        "pyzbar, which this app does not bundle).")

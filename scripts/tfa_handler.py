import pyotp
import qrcode
import io
import base64

class TFAHandler:
    """Handles Two-Factor Authentication (TOTP)."""

    @staticmethod
    def generate_secret() -> str:
        """Generate a random base32 OTP secret."""
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(secret: str, email: str, issuer_name: str = "EnterpriseApp") -> str:
        """Generate a provisioning URI for QR code generation."""
        return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer_name)

    @staticmethod
    def generate_qr_base64(uri: str) -> str:
        """Generate a base64 encoded QR code image from a URI."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()

    @staticmethod
    def verify_token(secret: str, token: str) -> bool:
        """Verify a 6-digit TOTP token."""
        totp = pyotp.TOTP(secret)
        return totp.verify(token)

# eps_plugin/tls.py
#
# Generate a self-signed TLS certificate for the local Electrum server.
# Uses only the Python standard library (ssl + subprocess via openssl),
# with a fallback to the `cryptography` package if available.

import os
import subprocess
import tempfile
import logging
from pathlib import Path

logger = logging.getLogger("eps.tls")


def generate_self_signed_cert(cert_path: str, key_path: str,
                               hostname: str = "localhost") -> bool:
    """
    Generate a self-signed certificate and private key.

    Returns True on success, False on failure.
    Tries `cryptography` first, then falls back to the `openssl` CLI.
    """
    # Don't overwrite if already present
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return True

    os.makedirs(os.path.dirname(cert_path), exist_ok=True)

    if _try_cryptography(cert_path, key_path, hostname):
        logger.info(f"TLS cert generated (cryptography): {cert_path}")
        return True

    if _try_openssl_cli(cert_path, key_path, hostname):
        logger.info(f"TLS cert generated (openssl CLI): {cert_path}")
        return True

    logger.error("Could not generate TLS certificate. "
                 "Install the `cryptography` package or ensure `openssl` is on PATH.")
    return False


def _try_cryptography(cert_path: str, key_path: str, hostname: str) -> bool:
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
    except ImportError:
        return False

    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Electrum Personal Server"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Restrict key file permissions
        os.chmod(key_path, 0o600)
        return True

    except Exception as e:
        logger.debug(f"cryptography cert gen failed: {e}")
        return False


def _try_openssl_cli(cert_path: str, key_path: str, hostname: str) -> bool:
    try:
        subj = f"/CN={hostname}/O=Electrum Personal Server"
        cmd = [
            "openssl", "req", "-new", "-x509",
            "-days", "3650",
            "-nodes",
            "-subj", subj,
            "-keyout", key_path,
            "-out", cert_path,
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        if result.returncode != 0:
            logger.debug(f"openssl failed: {result.stderr.decode()}")
            return False
        os.chmod(key_path, 0o600)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug(f"openssl CLI not available: {e}")
        return False


def default_cert_dir() -> str:
    """Return a sensible default directory for cert storage."""
    # Electrum's util.user_dir() was previously named get_user_dir()
    try:
        from electrum.util import user_dir
    except ImportError:
        from electrum.util import get_user_dir as user_dir
    return os.path.join(user_dir(), "eps_certs")


def default_cert_paths() -> tuple:
    d = default_cert_dir()
    return (os.path.join(d, "eps.crt"), os.path.join(d, "eps.key"))

import os
import ssl
import logging
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger("egress.tls")

CERT_DIR = Path(os.getenv("RAPHAEL_HOME", str(Path.home() / ".raphael"))) / "certs"


class TLSManager:
    def __init__(self, cert_dir: str = None):
        self.cert_dir = Path(cert_dir or CERT_DIR)
        self.cert_dir.mkdir(parents=True, exist_ok=True)

    def _ensure_ca(self):
        ca_key = self.cert_dir / "ca.key"
        ca_cert = self.cert_dir / "ca.pem"
        if ca_key.exists() and ca_cert.exists():
            return ca_key, ca_cert
        self._gen_ca(ca_key, ca_cert)
        return ca_key, ca_cert

    def _gen_ca(self, key_path: Path, cert_path: Path):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Raphael Egress CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Raphael Internal CA"),
        ])
        cert = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f"  Generated CA: {cert_path}")

    def cert_for_domain(self, domain: str):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        cert_path = self.cert_dir / f"{domain}.pem"
        key_path = self.cert_dir / f"{domain}.key"
        if cert_path.exists() and key_path.exists():
            return key_path, cert_path
        ca_key_path, ca_cert_path = self._ensure_ca()
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([
                   x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                   x509.NameAttribute(NameOID.COMMON_NAME, domain),
               ]))
               .sign(key, hashes.SHA256()))
        cert = (x509.CertificateBuilder()
                .subject_name(csr.subject)
                .issuer_name(ca_cert.subject)
                .public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f"  Generated cert for {domain}: {cert_path}")
        return key_path, cert_path

    def ssl_context_for_domain(self, domain: str, sni_hostname: str = None) -> ssl.SSLContext:
        _, cert_path = self.cert_for_domain(domain)
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(cert_path)
        if sni_hostname:
            ctx.sni_callback = lambda sock, name, ctx: None
        return ctx


def create_tls_context(verify: bool = True, sni_hostname: str = None) -> ssl.SSLContext:
    if not verify:
        logger.warning("TLS certificate verification disabled — MITM possible")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ctx = ssl.create_default_context()
    if sni_hostname:
        ctx.sni_callback = lambda sock, name, ctx: None
    return ctx

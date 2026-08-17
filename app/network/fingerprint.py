from __future__ import annotations

import asyncio
import re
import ssl
from datetime import datetime, timezone

from cryptography import x509

from app.domain.models import ServiceFingerprint


class ServiceFingerprinter:
    _TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443}
    _HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888}
    _BANNER_PORTS = {21, 22, 25, 110, 143, 587}

    def __init__(self, timeout_seconds: float = 1.2, banner_limit: int = 2048) -> None:
        self._timeout = timeout_seconds
        self._banner_limit = banner_limit

    async def fingerprint(self, ip: str, port: int, service: str) -> ServiceFingerprint:
        banner: str | None = None
        tls_version: str | None = None
        tls_cipher: str | None = None
        cert_expiry: datetime | None = None
        cert_subject: str | None = None

        if port in self._TLS_PORTS or service in {"https", "imaps", "pop3s", "ldaps"}:
            tls = await self._tls_handshake(ip, port)
            if tls is not None:
                tls_version, tls_cipher, cert_expiry, cert_subject = tls
                if port in self._HTTP_PORTS:
                    banner = await self._http_banner(ip, port, use_tls=True)
        elif port in self._HTTP_PORTS or service in {"http", "http-alt"}:
            banner = await self._http_banner(ip, port, use_tls=False)
        elif port in self._BANNER_PORTS:
            banner = await self._read_banner(ip, port)

        product, version = self._parse_product_version(banner)
        return ServiceFingerprint(
            product=product,
            version=version,
            banner=banner,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            certificate_expires_at=cert_expiry,
            certificate_subject=cert_subject,
        )

    async def _read_banner(self, ip: str, port: int) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self._timeout
            )
            data = await asyncio.wait_for(reader.read(self._banner_limit), timeout=self._timeout)
            writer.close()
            await writer.wait_closed()
        except (TimeoutError, OSError, ssl.SSLError):
            return None
        return self._clean_banner(data)

    async def _http_banner(self, ip: str, port: int, *, use_tls: bool) -> str | None:
        ssl_context: ssl.SSLContext | None = None
        if use_tls:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip,
                    port,
                    ssl=ssl_context,
                    server_hostname=ip if use_tls else None,
                ),
                timeout=self._timeout,
            )
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: SurNet-Guardian/0.2\r\n\r\n"
            writer.write(request.encode("ascii"))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(self._banner_limit), timeout=self._timeout)
            writer.close()
            await writer.wait_closed()
        except (TimeoutError, OSError, ssl.SSLError):
            return None
        return self._clean_banner(data)

    async def _tls_handshake(
        self, ip: str, port: int
    ) -> tuple[str | None, str | None, datetime | None, str | None] | None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=ip),
                timeout=self._timeout,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                writer.close()
                await writer.wait_closed()
                return None
            version = ssl_object.version()
            cipher_data = ssl_object.cipher()
            cipher = cipher_data[0] if cipher_data else None
            der_cert = ssl_object.getpeercert(binary_form=True)
            expiry: datetime | None = None
            subject: str | None = None
            if der_cert:
                certificate = x509.load_der_x509_certificate(der_cert)
                expiry = certificate.not_valid_after_utc
                subject = certificate.subject.rfc4514_string() or None
            writer.close()
            await writer.wait_closed()
            return version, cipher, expiry, subject
        except (TimeoutError, OSError, ssl.SSLError, ValueError):
            return None

    @staticmethod
    def _clean_banner(data: bytes) -> str | None:
        if not data:
            return None
        text = data.decode("utf-8", errors="replace").replace("\x00", " ")
        text = " ".join(text.split())[:1024]
        return text or None

    @staticmethod
    def _parse_product_version(banner: str | None) -> tuple[str | None, str | None]:
        if not banner:
            return None, None
        patterns = (
            (r"OpenSSH[_/-]([0-9][\w.\-p]+)", "OpenSSH"),
            (r"nginx/([0-9][\w.\-]+)", "nginx"),
            (r"Apache/([0-9][\w.\-]+)", "Apache HTTP Server"),
            (r"Microsoft-IIS/([0-9][\w.\-]+)", "Microsoft IIS"),
            (r"vsFTPd\s+([0-9][\w.\-]+)", "vsftpd"),
        )
        for pattern, product in patterns:
            match = re.search(pattern, banner, flags=re.IGNORECASE)
            if match:
                return product, match.group(1)
        server = re.search(r"Server:\s*([^\s/]+)/([0-9][^\s]*)", banner, flags=re.IGNORECASE)
        if server:
            return server.group(1), server.group(2)
        return None, None

from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.resolver


class DnsTxtResolver(Protocol):
    def lookup_txt(self, name: str) -> list[str]: ...


class DnsPythonTxtResolver:
    def __init__(self, resolver: dns.resolver.Resolver | None = None) -> None:
        self._resolver = resolver or dns.resolver.Resolver()

    def lookup_txt(self, name: str) -> list[str]:
        try:
            answers = self._resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.DNSException:
            return []

        values: list[str] = []
        for rdata in answers:
            # TXT rdata may be split into multiple character-strings.
            chunks = getattr(rdata, "strings", None)
            if chunks:
                text = b"".join(chunks).decode("utf-8", errors="replace")
            else:
                text = str(rdata).strip('"')
            values.append(text)
        return values


class StaticDnsTxtResolver:
    """Test double: map absolute name -> TXT values."""

    def __init__(self, records: dict[str, list[str]] | None = None) -> None:
        self.records = records or {}

    def lookup_txt(self, name: str) -> list[str]:
        key = name.rstrip(".").lower()
        return list(self.records.get(key, []))

    def set(self, name: str, values: list[str]) -> None:
        self.records[name.rstrip(".").lower()] = list(values)

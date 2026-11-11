"""server-certificate-lifecycle."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "server-certificate-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Server certificate upload->active->renamed->deleted->404 transitions."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-servercert-")

    cert = _self_signed_cert_and_key(ctx, common_name="sim2real-behav-cert.example.com")

    iam.upload_server_certificate(
        ServerCertificateName=name,
        CertificateBody=cert["cert_pem"],
        PrivateKey=cert["key_pem"],
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    active_name = name
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_server_certificate(ServerCertificateName=active_name)
        )
    )

    got = iam.get_server_certificate(ServerCertificateName=name)["ServerCertificate"]
    got_name = got["ServerCertificateMetadata"]["ServerCertificateName"]
    assert got_name == name, f"expected GetServerCertificate to echo {name!r}, got {got_name!r}"
    assert "BEGIN CERTIFICATE" in got["CertificateBody"], (
        f"expected a PEM certificate body, got {got['CertificateBody'][:80]!r}"
    )

    names = {c["ServerCertificateName"] for c in iam.list_server_certificates()["ServerCertificateMetadataList"]}
    assert name in names, f"expected {name!r} in ListServerCertificates, got {sorted(names)!r}"

    new_name = ctx.unique_name("sim2real-behav-servercert-renamed-")
    iam.update_server_certificate(ServerCertificateName=name, NewServerCertificateName=new_name)
    active_name = new_name

    old_read_code, old_read_msg = _error(lambda: iam.get_server_certificate(ServerCertificateName=name))
    assert old_read_code == "NoSuchEntity", f"expected the renamed-away name {name!r} to read NoSuchEntity, got {old_read_code!r}"
    want = f"The Server Certificate with name {name} cannot be found."
    assert old_read_msg == want, f"expected message {want!r}, got {old_read_msg!r}"

    # the renamed-away name is not just unreadable — it must reject a mutation too, not only a read.
    dead_target = ctx.unique_name("sim2real-behav-servercert-dead-")
    old_mutate_code, old_mutate_msg = _error(
        lambda: iam.update_server_certificate(ServerCertificateName=name, NewServerCertificateName=dead_target)
    )
    assert old_mutate_code == "NoSuchEntity", (
        f"expected UpdateServerCertificate on the renamed-away name {name!r} to fail NoSuchEntity, got {old_mutate_code!r}"
    )
    want = f"The Server Certificate with name {name} cannot be found."
    assert old_mutate_msg == want, f"expected message {want!r}, got {old_mutate_msg!r}"

    got = iam.get_server_certificate(ServerCertificateName=new_name)["ServerCertificate"]
    got_new_name = got["ServerCertificateMetadata"]["ServerCertificateName"]
    assert got_new_name == new_name, f"expected GetServerCertificate to echo the renamed name {new_name!r}, got {got_new_name!r}"

    iam.delete_server_certificate(ServerCertificateName=new_name)

    del_read_code, del_read_msg = _error(lambda: iam.get_server_certificate(ServerCertificateName=new_name))
    assert del_read_code == "NoSuchEntity", f"expected the deleted name {new_name!r} to read NoSuchEntity, got {del_read_code!r}"
    want = f"The Server Certificate with name {new_name} cannot be found."
    assert del_read_msg == want, f"expected message {want!r}, got {del_read_msg!r}"

    # a repeat delete on the now-gone name must fail, not succeed silently a second time.
    redelete_code, redelete_msg = _error(lambda: iam.delete_server_certificate(ServerCertificateName=new_name))
    assert redelete_code == "NoSuchEntity", f"expected a repeat delete of {new_name!r} to fail NoSuchEntity, got {redelete_code!r}"
    want = f"The Server Certificate with name {new_name} cannot be found."
    assert redelete_msg == want, f"expected message {want!r}, got {redelete_msg!r}"

    names_after = {c["ServerCertificateName"] for c in iam.list_server_certificates()["ServerCertificateMetadataList"]}
    assert new_name not in names_after, f"expected {new_name!r} absent from ListServerCertificates, got {sorted(names_after)!r}"


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _self_signed_cert_and_key(ctx, common_name: str) -> dict:
    require_tools("openssl")
    proc = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", f"/CN={common_name}",
            "-keyout", "/dev/stdout", "-out", "/dev/stdout",
        ],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0 or "BEGIN CERTIFICATE" not in proc.stdout:
        raise AssertionError(f"unreachable: openssl failed to generate a test certificate: {proc.stderr[:300]}")
    combined = proc.stdout
    key_start = combined.index("-----BEGIN PRIVATE KEY-----")
    cert_start = combined.index("-----BEGIN CERTIFICATE-----")
    if key_start < cert_start:
        key_pem, cert_pem = combined[key_start:cert_start], combined[cert_start:]
    else:
        cert_pem, key_pem = combined[cert_start:key_start], combined[key_start:]
    return {"cert_pem": cert_pem.strip() + "\n", "key_pem": key_pem.strip() + "\n"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

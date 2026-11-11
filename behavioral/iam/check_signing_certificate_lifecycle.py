"""signing-certificate-lifecycle."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "signing-certificate-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Signing certificate upload->status-updated->deleted transitions and removal from list."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-signcertuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    cert_pem = _self_signed_cert_pem(ctx, common_name="sim2real-behav-signcert.example.com")

    uploaded = iam.upload_signing_certificate(UserName=user_name, CertificateBody=cert_pem)["Certificate"]
    cert_id = uploaded["CertificateId"]
    assert uploaded["Status"] == "Active"
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_signing_certificate(UserName=user_name, CertificateId=cert_id)
        )
    )

    certs = {c["CertificateId"]: c for c in iam.list_signing_certificates(UserName=user_name)["Certificates"]}
    assert cert_id in certs
    assert certs[cert_id]["Status"] == "Active"

    iam.update_signing_certificate(UserName=user_name, CertificateId=cert_id, Status="Inactive")

    certs = {c["CertificateId"]: c for c in iam.list_signing_certificates(UserName=user_name)["Certificates"]}
    assert certs[cert_id]["Status"] == "Inactive"

    iam.delete_signing_certificate(UserName=user_name, CertificateId=cert_id)

    certs_after = {c["CertificateId"] for c in iam.list_signing_certificates(UserName=user_name)["Certificates"]}
    assert cert_id not in certs_after

    from botocore.exceptions import ClientError

    try:
        iam.update_signing_certificate(UserName=user_name, CertificateId=cert_id, Status="Active")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NoSuchEntity", f"expected NoSuchEntity for a mutation on a deleted certificate, got {code}"
        msg = exc.response["Error"].get("Message")
        want = f"The Certificate with id {cert_id} cannot be found."
        assert msg == want, f"NoSuchEntity message: wanted {want!r}, got {msg!r}"
    else:
        raise AssertionError("expected update_signing_certificate on a deleted certificate to fail, but it succeeded")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _self_signed_cert_pem(ctx, common_name: str) -> str:
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
    cert_start = combined.index("-----BEGIN CERTIFICATE-----")
    cert_end = combined.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
    return combined[cert_start:cert_end].strip() + "\n"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""update-domain-name-immutable-field-rejected."""
from __future__ import annotations

import datetime
import re
import time
import uuid

from behavioral_harness import tags

CHECK = "update-domain-name-immutable-field-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDomainName rejects a patch targeting the immutable /domainName path; the resource is untouched."""
    apigw = ctx.client("apigateway")
    domain = _dns_label(ctx.unique_name("sim2real-immdomain-")) + ".example.com"
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    cert_arn = _import_self_signed_cert(ctx, domain, teardown_deadline)
    apigw.create_domain_name(
        domainName=domain,
        endpointConfiguration={"types": ["REGIONAL"]},
        regionalCertificateArn=cert_arn,
        securityPolicy="TLS_1_0",
    )
    ctx.on_cleanup(lambda: _delete_domain_retrying(apigw, domain, teardown_deadline))

    # Positive control: UpdateDomainName on a mutable field succeeds on this target, so the
    # later rejection can only be about the immutable path -- not about every update failing.
    apigw.update_domain_name(
        domainName=domain,
        patchOperations=[{"op": "replace", "path": "/securityPolicy", "value": "TLS_1_2"}],
    )
    control = apigw.get_domain_name(domainName=domain)
    assert control["securityPolicy"] == "TLS_1_2", f"positive control did not take effect: {control}"

    other_name = _dns_label(ctx.unique_name("sim2real-otherdomain-")) + ".example.com"
    code, message = _error(
        lambda: apigw.update_domain_name(
            domainName=domain,
            patchOperations=[{"op": "replace", "path": "/domainName", "value": other_name}],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "/domainName Invalid request input", f"unexpected {code} message: {message!r}"

    # Effect absent: the domain name resource is untouched, including the field changed by the
    # positive control, and still reachable under its original name.
    got = apigw.get_domain_name(domainName=domain)
    assert got["domainName"] == domain, f"expected domainName {domain!r} unchanged, got {got['domainName']!r}"
    assert got["securityPolicy"] == "TLS_1_2", f"rejected patch must not disturb unrelated fields: {got}"

    # And the rejected new name was never actually created.
    lookup_code, lookup_message = _error(lambda: apigw.get_domain_name(domainName=other_name))
    assert lookup_code == "NotFoundException", lookup_code
    assert lookup_message == "Invalid domain name identifier specified", (
        f"unexpected {lookup_code} message: {lookup_message!r}"
    )


def _dns_label(raw: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError's (Code, Message). An unexpected success raises, so an
    accepted call is never reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _generate_self_signed_cert(common_name: str) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


# Inside the 900 s cleanup budget of behavioral/apigateway, one deadline shared by every teardown.
_TEARDOWN_RETRY_S = 780.0


def _delete_domain_retrying(apigw, domain: str, teardown_deadline: dict) -> None:
    """Delete the domain name once its securityPolicy update has settled: poll every 2 s to the
    cleanup deadline while domainNameStatus is UPDATING or PENDING, then delete; a domain that is
    already gone (NotFoundException) is done."""
    from botocore.exceptions import ClientError

    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    try:
        while True:
            status = apigw.get_domain_name(domainName=domain).get("domainNameStatus")
            if status not in ("UPDATING", "PENDING"):
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"domain name {domain} still {status} at the cleanup deadline; not deleted")
            time.sleep(2)
        apigw.delete_domain_name(domainName=domain)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_cert_retrying(acm, arn: str, teardown_deadline: dict) -> None:
    """Delete the certificate: done on success or ResourceNotFoundException; retry
    ResourceInUseException (held until the domain name deletion settles) every 2 s to the
    cleanup deadline, and raise everything else."""
    from botocore.exceptions import ClientError

    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _import_self_signed_cert(ctx, common_name: str, teardown_deadline: dict) -> str:
    acm = ctx.client("acm")
    cert_pem, key_pem = _generate_self_signed_cert(common_name)
    resp = acm.import_certificate(
        Certificate=cert_pem.encode(), PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real-behav", "Value": str(uuid.uuid4())}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying(acm, arn, teardown_deadline))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

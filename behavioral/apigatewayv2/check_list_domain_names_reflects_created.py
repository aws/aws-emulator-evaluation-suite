"""list-domain-names-reflects-created."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-domain-names-reflects-created"
GROUP = "data-plane"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDomainNames lists a new DomainName at once and omits it once deleted; GetDomainName then
    fails NotFoundException and an empty UpdateDomainName fails BadRequestException."""
    apigw = ctx.client("apigatewayv2")

    domain = ctx.unique_name("sim2real-behav-") + ".example.com"
    cert_arn = _import_self_signed_cert(ctx, domain)

    apigw.create_domain_name(
        DomainName=domain,
        Tags={"sim2real": "list-domain-names-reflects-created"},
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
    )

    def _cleanup():
        try:
            apigw.delete_domain_name(DomainName=domain)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    names = {item["DomainName"] for item in _list_all_domain_names(apigw)}
    assert domain in names, f"expected {domain!r} in GetDomainNames listing, got {sorted(names)!r}"

    apigw.delete_domain_name(DomainName=domain)

    def _still_listed():
        names_now = {item["DomainName"] for item in _list_all_domain_names(apigw)}
        return domain in names_now

    _poll_until(_still_listed, lambda listed: not listed, timeout_s=120, interval_s=5)

    read_err = _error(lambda: apigw.get_domain_name(DomainName=domain))
    assert read_err == ("NotFoundException", "Invalid domain name identifier specified"), (
        f"expected NotFoundException reading deleted domain {domain!r}, got {read_err!r}"
    )

    mutate_err = _error(lambda: apigw.update_domain_name(DomainName=domain))
    assert mutate_err == ("BadRequestException", "UpdateDomainName request cannot be empty or null"), (
        f"expected BadRequestException for an empty update of deleted domain {domain!r}, got {mutate_err!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _self_signed_cert(domain: str) -> tuple[bytes, bytes]:
    import subprocess
    import tempfile
    import os as _os

    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = _os.path.join(d, "key.pem")
        cert_path = _os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "365",
                "-nodes", "-keyout", key_path, "-out", cert_path, "-subj", f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        with open(key_path, "rb") as f:
            key = f.read()
        with open(cert_path, "rb") as f:
            cert = f.read()
    return cert, key


def _import_self_signed_cert(ctx, domain: str) -> str:
    cert, key = _self_signed_cert(domain)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert, PrivateKey=key)
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, arn))
    return arn


def _delete_cert_when_released(acm, cert_arn: str, attempts: int = 9, delay_s: float = 5.0) -> None:
    """ACM reports the certificate in use for a few seconds after the domain name that
    referenced it is deleted; retry through that window, bounded under the cleanup budget."""
    from botocore.exceptions import ClientError

    for attempt in range(attempts):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or attempt == attempts - 1:
                raise
            time.sleep(delay_s)


def _list_all_domain_names(apigw):
    items = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = apigw.get_domain_names(**kwargs)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

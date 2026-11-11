"""op-contract-listCertificates."""
from __future__ import annotations

import re
import time

CHECK = "op-contract-listCertificates"
GROUP = "error-semantics"
SERVICES = ["acm"]


from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Default ListCertificates lists an RSA_2048 certificate but not an EC_prime256v1 one, which
    Includes.keyTypes surfaces; SortBy without SortOrder is refused service-side with
    InvalidArgsException and the exact message."""
    acm = ctx.client("acm")

    rsa_domain = _unique_domain(ctx, "acmlistrsa")
    ec_domain = _unique_domain(ctx, "acmlistec")
    rsa_arn = acm.request_certificate(
        DomainName=rsa_domain,
        ValidationMethod="DNS",
        KeyAlgorithm="RSA_2048",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, rsa_arn))
    ec_arn = acm.request_certificate(
        DomainName=ec_domain,
        ValidationMethod="DNS",
        KeyAlgorithm="EC_prime256v1",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, ec_arn))
    _wait_describable(acm, rsa_arn)
    _wait_describable(acm, ec_arn)

    # success path: default ListCertificates (no Includes filter) surfaces the RSA_2048
    # certificate but not the EC certificate
    rsa_arns = _wait_listed(acm, {}, rsa_arn)
    assert rsa_arn in rsa_arns
    assert ec_arn not in rsa_arns, "default ListCertificates must not include non-RSA_2048 certs"

    # asking explicitly for EC_prime256v1 key types surfaces the EC certificate
    ec_arns = _wait_listed(acm, {"Includes": {"keyTypes": ["EC_prime256v1"]}}, ec_arn)
    assert ec_arn in ec_arns

    # SortBy requires SortOrder; neither is individually required, so botocore sends the
    # request and the service refuses it.
    from botocore.exceptions import ClientError

    try:
        acm.list_certificates(SortBy="CREATED_AT")
        raise AssertionError("expected service-side rejection for SortBy without SortOrder")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "InvalidArgsException", f"expected InvalidArgsException, got {code}"
        expected = (
            "Request contains either SortBy or SortOrder. "
            "Both SortBy and SortOrder parameters need to specified in the request."
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"


def _unique_domain(ctx, label: str) -> str:
    raw = ctx.unique_name(f"{label}-").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return f"{raw}.example.com"


def _wait_describable(acm, arn: str, timeout_s: float = 30.0, interval_s: float = 1.5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return acm.describe_certificate(CertificateArn=arn)["Certificate"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"certificate {arn} never became describable: {last_exc}")


def _wait_listed(acm, list_kwargs, target_arn, timeout_s: float = 45.0, interval_s: float = 2.0):
    """Poll ListCertificates (paginating up to a bound) until target_arn appears or
    timeout; returns the set of ARNs seen on the pass that found it (or the last pass)."""
    deadline = time.monotonic() + timeout_s
    seen: set[str] = set()
    while time.monotonic() < deadline:
        seen = set()
        next_token = None
        for _ in range(10):  # bounded pagination
            kwargs = dict(list_kwargs)
            kwargs["MaxItems"] = 200
            if next_token:
                kwargs["NextToken"] = next_token
            resp = acm.list_certificates(**kwargs)
            seen.update(c["CertificateArn"] for c in resp.get("CertificateSummaryList", []))
            next_token = resp.get("NextToken")
            if target_arn in seen or not next_token:
                break
        if target_arn in seen:
            return seen
        time.sleep(interval_s)
    return seen


def _safe_delete(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

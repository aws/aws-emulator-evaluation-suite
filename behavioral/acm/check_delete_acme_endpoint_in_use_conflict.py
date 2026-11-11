"""delete-acme-endpoint-in-use-conflict."""
from __future__ import annotations

import time

from behavioral_harness import tags


CHECK = "delete-acme-endpoint-in-use-conflict"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAcmeEndpoint with a dependent AcmeDomainValidation succeeds and cascades, as documented:
    the dependent validation becomes not-found instead of blocking the delete or dangling."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    domain = _unique_domain(ctx, "dvconflict")

    dv_resp = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "sim2real", "Value": ctx.unique_name("dvconflict-")}],
    )
    dv_arn = dv_resp["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_dv(ctx, dv_arn))

    # the dependent validation is describable before the cascade, and attached to this endpoint
    pre = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert pre["AcmeEndpointArn"] == endpoint_arn, (
        f"expected the domain validation to be attached to {endpoint_arn!r}; GOT={pre['AcmeEndpointArn']!r}"
    )

    # deleting the endpoint while a dependent validation exists succeeds (cascade),
    # not a ConflictException
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
    _wait_for_endpoint_gone(ctx, endpoint_arn)

    # the cascade removed the dependent validation too: describing it now 404s
    expected_message = f"Could not find ACME domain validation {dv_arn}."
    code, message = _error_code(lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn))
    assert code == "ResourceNotFoundException", (
        f"expected the cascade delete to remove the dependent AcmeDomainValidation; GOT={code!r} ({message!r})"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the dead id is not just unreadable, it is unusable: a mutation on it also fails not-found
    update_code, update_message = _error_code(
        lambda: acm.update_acme_domain_validation(
            AcmeDomainValidationArn=dv_arn, PrevalidationOptions={"DnsPrevalidation": {}}
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateAcmeDomainValidation on the cascade-deleted arn to 404; GOT={update_code!r}"
    )
    assert update_message == expected_message, f"expected message {expected_message!r}, got {update_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _unique_domain(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real-{tag}-").lower().replace("_", "-").strip("-")
    return f"{raw}.example.com"


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "sim2real", "Value": ctx.unique_name("dvconflict-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _wait_for_endpoint_gone(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            acm.describe_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} still describable after {timeout_s}s")


def _delete_endpoint(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    try:
        acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_dv_gone(ctx, dv_arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"AcmeDomainValidation {dv_arn} still describable after {timeout_s}s")


def _delete_dv(ctx, dv_arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    try:
        acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

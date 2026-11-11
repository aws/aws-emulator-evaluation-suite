"""create-acme-domain-validation-for-unowned-endpoint-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-acme-domain-validation-for-unowned-endpoint-denied"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAcmeDomainValidation against another account's AcmeEndpointArn is rejected; the
    caller's own endpoint is unaffected, and a validation on an endpoint it owns still succeeds."""
    acm = ctx.client("acm")
    sts = ctx.client("sts")

    endpoint_arn = _create_active_endpoint(ctx, acm, contact="NOT_REQUIRED")

    domain_own = _domain_name(ctx, "dv-own")
    dv_own_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_own,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "sim2real-check", "Value": domain_own}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(
        lambda: _ignore(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_own_arn))
    )

    baseline_arns = {v["AcmeDomainValidationArn"] for v in _list_domain_validations(acm, endpoint_arn)}
    assert baseline_arns == {dv_own_arn}, f"expected only the just-created validation, got {baseline_arns}"

    own_account = sts.get_caller_identity()["Account"]
    foreign_arn = _swap_account(endpoint_arn, _foreign_account_id(own_account))
    domain_foreign = _domain_name(ctx, "dv-foreign")

    code, message = _error_code(
        lambda: acm.create_acme_domain_validation(
            AcmeEndpointArn=foreign_arn,
            DomainName=domain_foreign,
            PrevalidationOptions={"DnsPrevalidation": {}},
        )
    )
    # A cross-account AcmeEndpointArn is rejected at input-validation time with
    # ValidationException rather than AccessDeniedException: the service refuses to even
    # consider the request against a foreign account ARN, which is the non-permissive outcome.
    assert code == "ValidationException", f"expected ValidationException, got {code} ({message!r})"
    expected_message = (
        "Resource identifier for acme-endpoint has a validation error: "
        "Same account ARN expected but got cross-account ARN"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the caller's own endpoint still lists exactly the one validation it had
    after_arns = {v["AcmeDomainValidationArn"] for v in _list_domain_validations(acm, endpoint_arn)}
    assert after_arns == baseline_arns, f"unowned attempt leaked into caller's own endpoint: {after_arns}"

    # positive control: a validation on the endpoint the caller *does* own still succeeds
    domain_control = _domain_name(ctx, "dv-control")
    dv_control_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_control,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "sim2real-check", "Value": domain_control}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(
        lambda: _ignore(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_control_arn))
    )
    assert dv_control_arn != dv_own_arn, f"expected a distinct control validation, got the same arn {dv_control_arn!r}"
    final_arns = {v["AcmeDomainValidationArn"] for v in _list_domain_validations(acm, endpoint_arn)}
    assert final_arns == {dv_own_arn, dv_control_arn}, (
        f"expected exactly the own+control validations, got {final_arns}"
    )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore(fn) -> None:
    fn()


def _domain_name(ctx, label: str) -> str:
    token = ctx.unique_name(f"sim2real-{label}-").lower().strip("-")
    return f"{token}.example.com"


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "sim2real-check", "Value": ctx.unique_name("acme-unowned-")}],
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(
    acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0
) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


def _list_domain_validations(acm, endpoint_arn: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"AcmeEndpointArn": endpoint_arn}
        if token:
            kwargs["NextToken"] = token
        resp = acm.list_acme_domain_validations(**kwargs)
        out.extend(resp.get("AcmeDomainValidations", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _swap_account(arn: str, new_account: str) -> str:
    parts = arn.split(":")
    parts[4] = new_account
    return ":".join(parts)


def _foreign_account_id(own_account: str) -> str:
    candidate = "111122223333"
    if candidate == own_account:
        candidate = "123456789013"
    return candidate


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

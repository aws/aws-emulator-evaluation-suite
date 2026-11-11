"""list-acme-accounts-nonexistent-endpoint."""
from __future__ import annotations

import time
import uuid
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-acme-accounts-nonexistent-endpoint"
GROUP = 'error-semantics'
SERVICES = ['acm']

def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]

def _bogus_acme_endpoint_arn(ctx):
    return f"arn:aws:acm:{ctx.region}:{_account_id(ctx)}:acme-endpoint/{uuid.uuid4()}"

def _wait_active(acm, arn, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"ACME endpoint {arn} reached FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"ACME endpoint {arn} never reached ACTIVE within {timeout_s}s")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAcmeAccounts on a nonexistent ACME endpoint fails with ResourceNotFoundException, after a
    positive control on an ACTIVE endpoint returns an empty account list."""
    acm = ctx.client("acm")
    if not hasattr(acm, "list_acme_accounts"):
        raise AssertionError("ListAcmeAccounts not present in the installed botocore model")

    real_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-laane-")}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=real_arn))
    _wait_active(acm, real_arn)

    control = acm.list_acme_accounts(AcmeEndpointArn=real_arn)
    assert control["AcmeAccounts"] == [], (
        f"expected no ACME accounts on a freshly created endpoint, got {control['AcmeAccounts']!r}"
    )

    bogus = _bogus_acme_endpoint_arn(ctx)
    try:
        result = acm.list_acme_accounts(AcmeEndpointArn=bogus)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"ListAcmeAccounts on a nonexistent endpoint succeeded: {result!r}")
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent ACME endpoint, got {code!r}"
    )
    expected_message = f"Could not find ACME endpoint {bogus}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

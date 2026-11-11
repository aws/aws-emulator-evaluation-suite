"""describe-nonexistent-acme-account-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-acme-account-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAcmeAccount for an AccountUrl on a well-formed but unknown endpoint raises ResourceNotFoundException."""
    acm = ctx.client("acm")
    account = _account_id(ctx)
    fake_endpoint_arn = f"arn:aws:acm:{ctx.region}:{account}:acme-endpoint/{uuid.uuid4()}"
    account_url = f"https://acme-v02.example.com/acme/acct/{uuid.uuid4().hex}"

    code, message = _error(
        lambda: acm.describe_acme_account(
            AcmeEndpointArn=fake_endpoint_arn, AccountUrl=account_url
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for unknown ACME account/endpoint, got {code!r}"
    )
    expected_message = f"Could not find ACME endpoint {fake_endpoint_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Run fn, which must be refused; return the (code, message) of the refusal."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

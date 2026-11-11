"""create-campaign-invalid-instance-id-pattern-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-campaign-invalid-instance-id-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["connectcampaignsv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCampaign with a connectInstanceId outside ^[-_.a-zA-Z0-9]+$ fails with ValidationException and
    its exact message, while a well-formed nonexistent one fails with ResourceNotFoundException and its
    exact message."""
    campaigns = ctx.client("connectcampaignsv2")

    control = _error(
        lambda: campaigns.create_campaign(
            name=ctx.unique_name("s2r-campaign-"),
            connectInstanceId=str(uuid.uuid4()),
        )
    )
    assert control["Code"] == "ResourceNotFoundException", (
        "expected the well-formed-but-nonexistent control to get ResourceNotFoundException, "
        f"got {control['Code']}"
    )
    expected_control = "Connect Instance does not exist or is not enabled to use Campaigns."
    assert control["Message"] == expected_control, (
        f"expected message {expected_control!r}, got {control['Message']!r}"
    )

    err = _error(
        lambda: campaigns.create_campaign(
            name=ctx.unique_name("s2r-campaign-"),
            connectInstanceId="not a valid instance id!",
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']}"
    expected = (
        "1 validation error detected: Value at 'connectInstanceId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [-_.a-zA-Z0-9]+"
    )
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"


def _error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

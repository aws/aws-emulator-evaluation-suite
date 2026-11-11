"""op-contract-describeByoipCidrs."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeByoipCidrs"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """DescribeByoipCidrs answers 200 with a ByoipCidrs list, and DryRun answers DryRunOperation with
    its exact message."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_byoip_cidrs")

    # positive control: MaxResults is accepted and the response is well-formed.
    response = ec2.describe_byoip_cidrs(MaxResults=10)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200, got {response['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert "ByoipCidrs" in response, "expected ByoipCidrs key in response"
    assert isinstance(response["ByoipCidrs"], list), (
        f"expected ByoipCidrs to be a list, got {type(response['ByoipCidrs'])!r}"
    )

    # error boundary: DryRun is a genuine server-side round trip -- the call is validated and
    # rejected with the documented DryRunOperation code rather than answered.
    dry_code, dry_message = _error(lambda: ec2.describe_byoip_cidrs(MaxResults=10, DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code!r}"
    assert dry_message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {dry_message!r}"


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

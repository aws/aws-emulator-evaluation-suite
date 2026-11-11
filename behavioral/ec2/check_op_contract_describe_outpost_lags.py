"""op-contract-describe-outpost-lags."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-outpost-lags"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeOutpostLags: success contract returns a list shape; DryRun=True rejects with DryRunOperation."""
    ec2 = ctx.client("ec2")

    # Success path: no account is guaranteed to own an Outpost, but the call
    # must succeed and return the documented list shape.
    resp = ec2.describe_outpost_lags()
    assert "OutpostLags" in resp, f"missing OutpostLags in response: {resp}"
    assert isinstance(resp["OutpostLags"], list), f"expected a list, got {resp['OutpostLags']!r}"

    # Error boundary: DryRun is documented for this operation. With valid
    # permissions the service must reject with DryRunOperation, never
    # silently succeed and never UnauthorizedOperation.
    code, msg = _client_error(lambda: ec2.describe_outpost_lags(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

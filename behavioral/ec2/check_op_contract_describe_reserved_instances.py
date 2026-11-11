"""op-contract-describe-reserved-instances."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-reserved-instances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeReservedInstances: success contract returns the documented
    list shape (empty is valid absent purchased RIs); DryRun=True rejects
    with DryRunOperation."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_reserved_instances()
    assert "ReservedInstances" in resp, f"expected a ReservedInstances key, got keys {sorted(resp)}"
    assert isinstance(resp["ReservedInstances"], list), (
        f"expected ReservedInstances to be a list, got {type(resp['ReservedInstances'])!r}"
    )
    for ri in resp["ReservedInstances"]:
        assert ri["State"] in ("payment-pending", "active", "payment-failed", "retired"), (
            f"unexpected ReservedInstances State {ri.get('State')!r} for {ri.get('ReservedInstancesId')!r}"
        )

    code, msg = _client_error(lambda: ec2.describe_reserved_instances(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    bad_id_code, bad_id_msg = _client_error(
        lambda: ec2.describe_reserved_instances(ReservedInstancesIds=["not-a-real-ri-id"])
    )
    assert bad_id_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a malformed ReservedInstancesId, got {bad_id_code}"
    )
    expected_bad_id_msg = "Invalid value 'not-a-real-ri-id' for ReservedInstancesId."
    assert bad_id_msg == expected_bad_id_msg, f"expected message {expected_bad_id_msg!r}, got {bad_id_msg!r}"


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

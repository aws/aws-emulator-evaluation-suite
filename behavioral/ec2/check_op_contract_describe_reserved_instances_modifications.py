"""op-contract-describe-reserved-instances-modifications."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-reserved-instances-modifications"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeReservedInstancesModifications answers with a list of modifications in a documented
    status, and an unsupported filter name fails with InvalidParameterValue and its exact message."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_reserved_instances_modifications()
    assert "ReservedInstancesModifications" in resp, (
        f"expected a ReservedInstancesModifications key, got keys {sorted(resp)!r}"
    )
    mods = resp["ReservedInstancesModifications"]
    assert isinstance(mods, list), f"expected ReservedInstancesModifications to be a list, got {type(mods).__name__}"
    for mod in mods:
        assert mod["Status"] in ("processing", "fulfilled", "failed"), (
            f"expected Status in (processing, fulfilled, failed), got {mod.get('Status')!r}"
        )

    code, msg = _client_error(
        lambda: ec2.describe_reserved_instances_modifications(
            Filters=[{"Name": "totally-bogus-filter-key", "Values": ["x"]}]
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected_msg = "The filter 'totally-bogus-filter-key' is invalid"
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

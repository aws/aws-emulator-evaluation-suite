"""describe-locked-snapshots-invalid-filter-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-locked-snapshots-invalid-filter-name-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeLockedSnapshots rejects a filter name outside its one documented filter
    (lock-state), while lock-state itself is accepted.
    """
    ec2 = ctx.client("ec2")

    code, message = _error(
        lambda: ec2.describe_locked_snapshots(Filters=[{"Name": "sim2real-bogus-filter", "Values": ["x"]}])
    )
    assert code == "InvalidFilter", f"expected InvalidFilter, got {code!r}"
    expected_message = "'sim2real-bogus-filter' for filter is not valid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: the legal neighbour -- the one documented filter name -- is accepted
    resp = ec2.describe_locked_snapshots(Filters=[{"Name": "lock-state", "Values": ["governance"]}])
    assert "Snapshots" in resp, sorted(resp)
    assert isinstance(resp["Snapshots"], list), f"expected Snapshots to be a list, got {resp['Snapshots']!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator answering a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

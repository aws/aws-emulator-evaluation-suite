"""op-contract-describe-id-format."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-id-format"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIdFormat for instance returns one status with UseLongIds true, the unscoped call lists
    instance and volume, and an unknown resource type fails with InvalidResourceType.Unknown and its
    exact message."""
    ec2 = ctx.client("ec2")

    scoped = ec2.describe_id_format(Resource="instance")["Statuses"]
    assert len(scoped) == 1, f"expected exactly one status entry for 'instance', got {scoped}"
    entry = scoped[0]
    assert entry["Resource"] == "instance", f"expected Resource 'instance', got {entry['Resource']!r}"
    # Every resource type's opt-out deadline (2016-12-14 for the original set, 2018-08-14 for the
    # rest) has passed, so long IDs are mandatory account-wide: UseLongIds reports True everywhere.
    assert entry["UseLongIds"] is True, f"expected UseLongIds True for 'instance', got {entry['UseLongIds']!r}"

    unscoped = ec2.describe_id_format()["Statuses"]
    resources = {item["Resource"] for item in unscoped}
    assert "instance" in resources and "volume" in resources, (
        f"expected the full resource-type status set, got {resources}"
    )

    # Error boundary: an unsupported resource type is rejected, not silently returned empty.
    code, message = _error(lambda: ec2.describe_id_format(Resource="sim2real-not-a-real-resource-type"))
    assert code == "InvalidResourceType.Unknown", f"expected InvalidResourceType.Unknown, got {code}"
    assert message == "Invalid resource type", message


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

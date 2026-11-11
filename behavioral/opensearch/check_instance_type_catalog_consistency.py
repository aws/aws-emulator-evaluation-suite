"""instance-type-catalog-consistency."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-type-catalog-consistency"
GROUP = 'catalog'
SERVICES = ['opensearch']


def _error_code(fn) -> tuple:
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """t3.small.search from ListInstanceTypeDetails has a data-role entry in
    DescribeInstanceTypeLimits for the same EngineVersion; an Elasticsearch-suffixed type raises
    ValidationException."""
    osc = ctx.client("opensearch")
    engine_version = "OpenSearch_2.11"

    details = osc.list_instance_type_details(EngineVersion=engine_version)["InstanceTypeDetails"]
    assert len(details) > 0, "expected a non-empty instance-type catalog"
    instance_type = next(
        (d["InstanceType"] for d in details if d["InstanceType"] == "t3.small.search"), None
    )
    assert instance_type is not None, (
        f"expected t3.small.search in catalog, got sample {details[:3]}"
    )

    limits = osc.describe_instance_type_limits(
        InstanceType=instance_type, EngineVersion=engine_version
    )["LimitsByRole"]
    assert "data" in limits, f"expected a 'data' role entry, got {limits}"

    code, message = _error_code(
        lambda: osc.describe_instance_type_limits(
            InstanceType="m3.xlarge.elasticsearch", EngineVersion=engine_version
        )
    )
    # The message enumerates every instance type AWS offers, a list that grows with each launch,
    # so only the stable prefix is asserted exactly.
    assert code == "ValidationException", (
        f"expected ValidationException for an incompatible legacy Elasticsearch-suffixed "
        f"instance type + modern OpenSearch engine version, got {code}"
    )
    prefix = (
        "1 validation error detected: Value 'm3.xlarge.elasticsearch' at 'instanceType' failed "
        "to satisfy constraint: Member must satisfy enum value set: ["
    )
    assert message.startswith(prefix) and message.endswith("]"), (
        f"expected the enum-constraint refusal {prefix!r}...], got {message!r}"
    )
    assert "t3.small.search" in message[len(prefix):], (
        f"expected the enum value set to list t3.small.search, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

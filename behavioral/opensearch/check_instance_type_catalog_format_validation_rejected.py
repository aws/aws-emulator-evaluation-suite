"""instance-type-catalog-format-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-type-catalog-format-validation-rejected"
GROUP = "catalog"
SERVICES = ["opensearch"]

_ENGINE_VERSION = "OpenSearch_2.11"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceTypeLimits rejects an EngineVersion that meets the length bound but not
    the version pattern, and ListInstanceTypeDetails rejects an InstanceType unknown to the
    requested AZ once RetrieveAZs is requested, each with its exact ValidationException message."""
    os_client = ctx.client("opensearch")

    # Positive control: a supported engine version and instance type both resolve.
    details = os_client.list_instance_type_details(EngineVersion=_ENGINE_VERSION).get(
        "InstanceTypeDetails", []
    )
    names = {d["InstanceType"] for d in details}
    assert "t3.small.search" in names, (
        f"expected t3.small.search among supported instance types, got {sorted(names)[:5]}"
    )
    limits = os_client.describe_instance_type_limits(
        InstanceType="t3.small.search", EngineVersion=_ENGINE_VERSION
    )
    assert limits.get("LimitsByRole"), "expected LimitsByRole for a supported type/version pair"

    # EngineVersion meets the model's 14-18 character length bound but not its
    # Elasticsearch_X.Y|OpenSearch_X.Y pattern, so the request reaches the service.
    bad_pattern_version = "XXXXXXXXXXXXXX"
    assert 14 <= len(bad_pattern_version) <= 18, len(bad_pattern_version)
    code, message = _error(
        lambda: os_client.describe_instance_type_limits(
            InstanceType="t3.small.search", EngineVersion=bad_pattern_version
        )
    )
    assert code == "ValidationException", (
        f"DescribeInstanceTypeLimits: expected ValidationException for a non-pattern-matching "
        f"EngineVersion, got {code}"
    )
    expected = (
        f"1 validation error detected: Value '{bad_pattern_version}' at 'engineVersion' failed "
        r"to satisfy constraint: Member must satisfy regular expression pattern: "
        r"^Elasticsearch_[0-9]{1}\.[0-9]{1,2}$|^OpenSearch_[0-9]{1,2}\.[0-9]{1,2}$"
    )
    assert message == expected, f"DescribeInstanceTypeLimits: got message {message!r}"

    # A well-formed instance type that is not offered in any AZ is only graded once RetrieveAZs
    # asks the service to resolve it against a zone; without that flag the parameter is unused.
    bad_type = "not.a.real.search"
    code, message = _error(
        lambda: os_client.list_instance_type_details(
            EngineVersion=_ENGINE_VERSION, InstanceType=bad_type, RetrieveAZs=True
        )
    )
    assert code == "ValidationException", (
        f"ListInstanceTypeDetails: expected ValidationException for an AZ-unsupported instance "
        f"type, got {code}"
    )
    expected = f"The AZ doesn't support instance type :{bad_type}"
    assert message == expected, f"ListInstanceTypeDetails: got message {message!r}"


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

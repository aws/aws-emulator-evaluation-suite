"""discovered-resource-counts-and-config-history."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


CHECK = "discovered-resource-counts-and-config-history"
GROUP = 'resource-config'
SERVICES = ['config']

# ResourceId's modeled max length (com.amazonaws.configservice#ResourceId, length trait max=768).
_RESOURCE_ID_MAX_LEN = 768


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDiscoveredResourceCounts returns totalDiscoveredResources overall and per type, and
    GetResourceConfigHistory fails with ResourceNotDiscoveredException for an undiscovered resource and
    with ValidationException for an over-long resourceId, each with its exact message."""
    cfg = ctx.client("config")

    counts = cfg.get_discovered_resource_counts()
    assert "totalDiscoveredResources" in counts, counts
    assert isinstance(counts["resourceCounts"], list), counts

    # a per-type query is also well-formed
    typed = cfg.get_discovered_resource_counts(resourceTypes=["AWS::S3::Bucket"])
    assert "totalDiscoveredResources" in typed, typed

    # History for a never-recorded resource is a hard not-found, NOT an empty list.
    never_discovered = ctx.unique_name("sim2real-behav-never-discovered-")
    code, message = _error(
        lambda: cfg.get_resource_config_history(
            resourceType="AWS::S3::Bucket",
            resourceId=never_discovered,
        )
    )
    assert code == "ResourceNotDiscoveredException", (code, message)
    assert message == (
        f"Resource {never_discovered} of resourceType:AWS::S3::Bucket is unknown or has not "
        "been discovered"
    ), message

    # A resourceId over the API's own modeled length limit is a DIFFERENT rejection
    # (ValidationException), proving the not-found path above is specific rather than a
    # blanket catch-all that would also misclassify this as "not discovered".
    too_long = "x" * (_RESOURCE_ID_MAX_LEN + 1)
    code, message = _error(
        lambda: cfg.get_resource_config_history(
            resourceType="AWS::S3::Bucket",
            resourceId=too_long,
        )
    )
    assert code == "ValidationException", (code, message)
    assert message == (
        f"1 validation error detected: Value '{too_long}' at 'resourceId' failed to satisfy "
        f"constraint: Member must have length less than or equal to {_RESOURCE_ID_MAX_LEN}"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""change-tags-for-resource-unknown-health-check-rejected."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-tags-for-resource-unknown-health-check-rejected"
GROUP = "tags"
SERVICES = ["route53"]


def _error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _current_tags(r53, resource_id: str) -> dict:
    return {
        t["Key"]: t["Value"]
        for t in r53.list_tags_for_resource(ResourceType="healthcheck", ResourceId=resource_id)[
            "ResourceTagSet"
        ]["Tags"]
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ChangeTagsForResource on a well-formed but nonexistent health check id answers
    NoSuchHealthCheck, while the identical call against a real health check succeeds.
    """
    r53 = ctx.client("route53")
    hc_fqdn = ctx.unique_name("sim2real-behav-ctu").lower() + ".invalid"
    created = r53.create_health_check(
        CallerReference=ctx.unique_name("sim2real-behav-ctu-cr-"),
        HealthCheckConfig={
            "FullyQualifiedDomainName": hc_fqdn,
            "Port": 80,
            "Type": "HTTP",
            "RequestInterval": 30,
            "FailureThreshold": 3,
        },
    )
    hc_id = created["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda i=hc_id: r53.delete_health_check(HealthCheckId=i))

    add_tags = [{"Key": "env", "Value": "test"}]

    # Positive control: tagging the real health check succeeds and is read back.
    r53.change_tags_for_resource(ResourceType="healthcheck", ResourceId=hc_id, AddTags=add_tags)
    assert _current_tags(r53, hc_id) == {"env": "test"}, _current_tags(r53, hc_id)

    # Break: the identical call against a well-formed but nonexistent health check id.
    unknown_id = str(uuid.uuid4())
    err = _error(
        lambda: r53.change_tags_for_resource(
            ResourceType="healthcheck", ResourceId=unknown_id, AddTags=add_tags
        )
    )
    assert err.get("Code") == "NoSuchHealthCheck", (
        f"expected NoSuchHealthCheck tagging an unknown health check {unknown_id!r}, got {err!r}"
    )
    assert err.get("Message") == f"A health check with id {unknown_id} does not exist.", err

    # The refused call created no tags on the unknown id (there is nothing to tag), and left
    # the real health check's own tags untouched.
    assert _current_tags(r53, hc_id) == {"env": "test"}, _current_tags(r53, hc_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

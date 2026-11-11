"""health-check-tags."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "health-check-tags"
GROUP = 'health-check'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _health_check_fqdn(ctx):
    """A name under the reserved .invalid TLD: it never resolves, so the health check probes no host."""
    return f"{ctx.unique_name('sim2real-behav-hc').lower()}.invalid"


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ChangeTagsForResource on a health check is reflected by ListTagsForResource and
    ListTagsForResources, overwrite-in-place on re-add, and removal — including a not-found
    negative on a well-formed but nonexistent health check id."""
    r53 = ctx.client("route53")
    resp = r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={"FullyQualifiedDomainName": _health_check_fqdn(ctx), "Port": 80, "Type": "HTTP",
                            "RequestInterval": 30, "FailureThreshold": 3},
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda i=hc_id: r53.delete_health_check(HealthCheckId=i))

    def current_tags():
        return {
            t["Key"]: t["Value"]
            for t in r53.list_tags_for_resource(ResourceType="healthcheck", ResourceId=hc_id)[
                "ResourceTagSet"
            ]["Tags"]
        }

    r53.change_tags_for_resource(
        ResourceType="healthcheck",
        ResourceId=hc_id,
        AddTags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    assert current_tags() == {"env": "test", "owner": "fidelity"}, current_tags()

    # AddTags on an existing key overwrites in place; RemoveTagKeys deletes — in the same call.
    r53.change_tags_for_resource(
        ResourceType="healthcheck",
        ResourceId=hc_id,
        AddTags=[{"Key": "env", "Value": "prod"}],
        RemoveTagKeys=["owner"],
    )
    assert current_tags() == {"env": "prod"}, current_tags()

    # The batch read path must agree with the single-resource read path.
    batch = r53.list_tags_for_resources(ResourceType="healthcheck", ResourceIds=[hc_id])
    sets = {
        s["ResourceId"]: {t["Key"]: t["Value"] for t in s["Tags"]}
        for s in batch["ResourceTagSets"]
    }
    assert sets.get(hc_id) == {"env": "prod"}, sets

    r53.change_tags_for_resource(ResourceType="healthcheck", ResourceId=hc_id, RemoveTagKeys=["env"])
    assert current_tags() == {}, current_tags()

    # A well-formed but nonexistent health check id must be a clean not-found rather than an
    # empty tag set.
    unknown_id = str(uuid.uuid4())
    err = _client_error(
        lambda: r53.list_tags_for_resource(ResourceType="healthcheck", ResourceId=unknown_id)
    )
    assert err["Code"] == "NoSuchHealthCheck", (
        f"expected NoSuchHealthCheck for an unknown health check id, got {err}"
    )
    assert err["Message"] == f"A health check with id {unknown_id} does not exist.", err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

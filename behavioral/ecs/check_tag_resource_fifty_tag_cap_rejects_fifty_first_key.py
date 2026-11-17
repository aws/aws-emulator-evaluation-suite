"""tag-resource-fifty-tag-cap-rejects-fifty-first-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-fifty-tag-cap-rejects-fifty-first-key"
GROUP = "negative-classes"
SERVICES = ["ecs"]


def _error(fn):
    """The (code, message) of the ClientError fn() raises; a call that succeeds raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster already holding the maximum 50 tags accepts TagResource overwriting one of
    those keys, but rejects adding a 51st distinct key with ClientException 'Tag Limit Exceeded.'.
    """
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-tagcap-")
    cluster = ecs.create_cluster(clusterName=name)["cluster"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    arn = cluster["clusterArn"]

    fifty_keys = [f"sim2real-k{i}" for i in range(50)]
    ecs.tag_resource(resourceArn=arn, tags=[{"key": k, "value": "v"} for k in fifty_keys])
    at_cap = {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert set(at_cap) == set(fifty_keys), f"expected exactly the 50 applied keys, got {sorted(at_cap)!r}"

    code, message = _error(
        lambda: ecs.tag_resource(resourceArn=arn, tags=[{"key": "sim2real-k50", "value": "v"}])
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    assert message == "Tag Limit Exceeded.", f"unexpected message: {message!r}"
    after_rejection = {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert "sim2real-k50" not in after_rejection, (
        f"the rejected 51st key must not have been persisted, got {sorted(after_rejection)!r}"
    )
    assert set(after_rejection) == set(fifty_keys), (
        f"the existing 50 tags must be unchanged by the rejected call, got {sorted(after_rejection)!r}"
    )

    ecs.tag_resource(resourceArn=arn, tags=[{"key": "sim2real-k0", "value": "updated"}])
    after_overwrite = {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert after_overwrite.get("sim2real-k0") == "updated", (
        f"overwriting an already-tagged key at the cap must still succeed, got {after_overwrite.get('sim2real-k0')!r}"
    )
    assert set(after_overwrite) == set(fifty_keys), (
        f"overwrite at the cap must not change the key set, got {sorted(after_overwrite)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

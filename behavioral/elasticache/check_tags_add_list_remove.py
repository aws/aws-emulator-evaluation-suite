"""tags-add-list-remove."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, actual = _error(fn)
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code} ({actual!r})"
    assert actual == expected[1], f"{expected[0]}: expected message {expected[1]!r}, got {actual!r}"
    return code

def _delete_parameter_group_when_ready(ec, name, timeout_s=300, interval_s=10):
    """Delete a cache parameter group, retrying while it is still applying (InvalidState)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_parameter_group(CacheParameterGroupName=name)
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code") or ""
            if "NotFound" in code:
                return
            if _fault_base(code) != "InvalidCacheParameterGroupState":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

CHECK = "tags-add-list-remove"
GROUP = 'tags'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags on a parameter group's ARN are added, overwritten and removed as ListTagsForResource shows; removing an
    absent key, listing a missing group's ARN and tagging the deleted group fail with TagNotFound and
    CacheParameterGroupNotFound and their exact messages."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-ecpg-tags-")
    resp = ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="fidelity check tags",
    )
    ctx.on_cleanup(lambda: _delete_parameter_group_when_ready(ec, name, timeout_s=60))
    arn = resp["CacheParameterGroup"]["ARN"]

    ec.add_tags_to_resource(
        ResourceName=arn, Tags=[{"Key": "env", "Value": "fidelity"}],
    )
    tags = ec.list_tags_for_resource(ResourceName=arn)["TagList"]
    assert {"Key": "env", "Value": "fidelity"} in tags, tags

    # AddTags is an upsert on an existing key, not a duplicate insert.
    ec.add_tags_to_resource(
        ResourceName=arn, Tags=[{"Key": "env", "Value": "fidelity2"}],
    )
    tags = ec.list_tags_for_resource(ResourceName=arn)["TagList"]
    env_tags = [t for t in tags if t["Key"] == "env"]
    assert env_tags == [{"Key": "env", "Value": "fidelity2"}], tags

    ec.remove_tags_from_resource(ResourceName=arn, TagKeys=["env"])
    tags_after = ec.list_tags_for_resource(ResourceName=arn)["TagList"]
    assert all(t["Key"] != "env" for t in tags_after), tags_after

    _assert_error(lambda: ec.remove_tags_from_resource(
        ResourceName=arn, TagKeys=["never-existed"],
    ), ("TagNotFoundFault", "Failing request. These tags are not present : never-existed"))

    # A well-formed ARN naming a resource that does not exist is a NotFound,
    # not an ARN-syntax problem.
    ghost = ctx.unique_name("sim2real-behav-ecpg-ghost-")
    ghost_arn = arn.rsplit(":", 1)[0] + ":" + ghost
    _assert_error(
        lambda: ec.list_tags_for_resource(ResourceName=ghost_arn),
        ("CacheParameterGroupNotFoundFault",
        f"{ghost} is not present"),
    )

    ec.delete_cache_parameter_group(CacheParameterGroupName=name)

    # The delete must be real: an independent read confirms gone, and a mutation
    # against the dead id fails the same way the ghost ARN did above.
    _assert_error(
        lambda: ec.describe_cache_parameter_groups(CacheParameterGroupName=name),
        ("CacheParameterGroupNotFoundFault",
        f"CacheParameterGroup {name} not found."),
    )
    _assert_error(
        lambda: ec.add_tags_to_resource(
            ResourceName=arn, Tags=[{"Key": "env", "Value": "post-delete"}],
        ),
        ("CacheParameterGroupNotFoundFault",
        f"{name} is not present"),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""tags-invalid-arn."""
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

def _delete_parameter_group_when_ready(ec, name, timeout_s=60, interval_s=5):
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

CHECK = "tags-invalid-arn"
GROUP = 'tags'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource and AddTagsToResource on "not-a-real-arn" fail with InvalidARNFault "Input ARN
    string does not have 7 components.", while tagging a real parameter group's ARN succeeds and is listed."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-ecpg-arn-")
    resp = ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="fidelity check invalid arn control",
    )
    ctx.on_cleanup(lambda: _delete_parameter_group_when_ready(ec, name))
    arn = resp["CacheParameterGroup"]["ARN"]

    ec.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": "env", "Value": "control"}])
    control_tags = ec.list_tags_for_resource(ResourceName=arn)["TagList"]
    assert {"Key": "env", "Value": "control"} in control_tags, control_tags

    _assert_error(
        lambda: ec.list_tags_for_resource(ResourceName="not-a-real-arn"),
        ("InvalidARNFault",
        "Input ARN string does not have 7 components."),
    )
    _assert_error(
        lambda: ec.add_tags_to_resource(
            ResourceName="not-a-real-arn", Tags=[{"Key": "k", "Value": "v"}],
        ),
        ("InvalidARNFault",
        "Input ARN string does not have 7 components."),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

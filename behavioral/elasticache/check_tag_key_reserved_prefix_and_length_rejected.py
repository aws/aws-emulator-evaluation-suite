"""tag-key-reserved-prefix-and-length-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-key-reserved-prefix-and-length-rejected"
GROUP = 'tags'
SERVICES = ['elasticache']

_FAMILY = "redis7"
# Tag keys are 1-128 characters, values 0-256, and the `aws:` prefix is reserved. None is in
# the service model, so botocore does not validate them and the service enforces all three.
_KEY_MAX = 128
_VALUE_MAX = 256


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _error(fn, what):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what}: expected a ClientError but the call SUCCEEDED (over-permissive)")


def _assert_error(fn, expected, what):
    """Assert fn() fails with the (code, message) pair `expected`, the code Fault/Exception-suffix
    normalized and the message exact."""
    code, actual = _error(fn, what)
    assert _fault_base(code) == _fault_base(expected[0]), (
        f"{what}: expected {expected[0]}, got {code} ({actual!r})"
    )
    assert actual == expected[1], f"{what}: expected message {expected[1]!r}, got {actual!r}"
    return code


def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None


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


def _tag_map(ec, arn):
    """ListTagsForResource as a plain {key: value} dict."""
    return {
        t["Key"]: t.get("Value", "")
        for t in ec.list_tags_for_resource(ResourceName=arn).get("TagList", [])
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A 128-char tag key and 256-char value are accepted; a 129-char key, 257-char value or
    `aws:` key is refused with InvalidParameterValue and its exact message, tags unchanged.

    Reference: https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Tagging-Resources.html
    """
    # A cache parameter group is taggable, not billable and provisions synchronously.
    ec = ctx.client("elasticache")

    group = ctx.unique_name("sim2real-behav-ecpg-tags-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=group,
        CacheParameterGroupFamily=_FAMILY,
        Description="sim2real tag contract-limit check",
    )
    ctx.on_cleanup(lambda: _delete_parameter_group_when_ready(ec, group))

    described = _describe_one(
        ec.describe_cache_parameter_groups,
        "CacheParameterGroups",
        "CacheParameterGroupName",
        group,
    )
    assert described is not None, f"{group} did not resolve after create"
    arn = described.get("ARN")
    assert arn and arn.startswith("arn:"), (
        f"DescribeCacheParameterGroups must return a real ARN to tag against, got {arn!r}"
    )

    max_key = "s" + "k" * (_KEY_MAX - 1)
    max_value = "v" * _VALUE_MAX
    assert len(max_key) == _KEY_MAX and len(max_value) == _VALUE_MAX, (
        f"test setup: expected key len {_KEY_MAX} value len {_VALUE_MAX}, "
        f"got {len(max_key)} / {len(max_value)}"
    )
    ec.add_tags_to_resource(
        ResourceName=arn,
        Tags=[{"Key": max_key, "Value": max_value}],
    )
    baseline = _tag_map(ec, arn)
    assert baseline == {max_key: max_value}, (
        f"the {_KEY_MAX}-char key / {_VALUE_MAX}-char value boundary tag must be accepted "
        f"and read back exactly; ListTagsForResource returned "
        f"{ {k[:12] + '...': len(v) for k, v in baseline.items()} }"
    )

    _assert_error(
        lambda: ec.add_tags_to_resource(
            ResourceName=arn,
            Tags=[{"Key": "aws:sim2real-forged", "Value": "forged"}],
        ),
        ("InvalidParameterValueException", 'Tag keys cannot start with the reserved prefix "aws:".'),
        "tag key with the reserved 'aws:' prefix",
    )
    after_reserved = _tag_map(ec, arn)
    assert after_reserved == baseline, (
        f"REJECTED AddTagsToResource still mutated the tag set: keys are now "
        f"{sorted(k[:16] for k in after_reserved)}"
    )
    assert not any(k.startswith("aws:") for k in after_reserved), (
        f"an aws:-prefixed key was persisted: {sorted(after_reserved)}"
    )

    over_key = "s" + "k" * _KEY_MAX
    assert len(over_key) == _KEY_MAX + 1, (
        f"test setup: expected over_key len {_KEY_MAX + 1}, got {len(over_key)}"
    )
    _assert_error(
        lambda: ec.add_tags_to_resource(
            ResourceName=arn,
            Tags=[{"Key": over_key, "Value": "x"}],
        ),
        (
            "InvalidParameterValueException",
            f"Tag keys must be between 1 and {_KEY_MAX} characters in length.",
        ),
        f"tag key of {_KEY_MAX + 1} characters (limit {_KEY_MAX})",
    )
    assert _tag_map(ec, arn) == baseline, (
        f"REJECTED over-length key still mutated the tag set: {sorted(_tag_map(ec, arn))}"
    )

    over_value = "v" * (_VALUE_MAX + 1)
    _assert_error(
        lambda: ec.add_tags_to_resource(
            ResourceName=arn,
            Tags=[{"Key": "sim2real-overlong-value", "Value": over_value}],
        ),
        (
            "InvalidParameterValueException",
            f"Tag values must be between 0 and {_VALUE_MAX} characters in length.",
        ),
        f"tag value of {_VALUE_MAX + 1} characters (limit {_VALUE_MAX})",
    )
    final_reject_state = _tag_map(ec, arn)
    assert final_reject_state == baseline, (
        f"REJECTED over-length value still mutated the tag set: "
        f"{sorted(final_reject_state)}"
    )
    assert "sim2real-overlong-value" not in final_reject_state, (
        "the rejected tag's key was persisted with a truncated value"
    )

    ec.remove_tags_from_resource(ResourceName=arn, TagKeys=[max_key])
    assert _tag_map(ec, arn) == {}, (
        f"control case failed: RemoveTagsFromResource left {sorted(_tag_map(ec, arn))}"
    )
    ec.add_tags_to_resource(
        ResourceName=arn,
        Tags=[{"Key": "sim2real-control", "Value": "ok"}],
    )
    assert _tag_map(ec, arn) == {"sim2real-control": "ok"}, (
        f"control case failed: after three rejections a legal tag no longer applies; "
        f"tag set is {_tag_map(ec, arn)}"
    )

    _delete_parameter_group_when_ready(ec, group)

    described_after_delete = _describe_one(
        ec.describe_cache_parameter_groups,
        "CacheParameterGroups",
        "CacheParameterGroupName",
        group,
    )
    assert described_after_delete is None, (
        f"{group} still described after delete: {described_after_delete}"
    )
    _assert_error(
        lambda: ec.add_tags_to_resource(
            ResourceName=arn,
            Tags=[{"Key": "sim2real-post-delete", "Value": "x"}],
        ),
        ("CacheParameterGroupNotFoundFault", f"{group} is not present"),
        "AddTagsToResource against the deleted parameter group's ARN",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

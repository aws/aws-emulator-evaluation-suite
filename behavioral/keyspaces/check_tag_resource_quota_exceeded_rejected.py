"""tag-resource-quota-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["keyspaces"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Adding tags past the 50-tags-per-resource limit is rejected (empirically ValidationException
    on real AWS, not silently truncated or accepted), and no overflow tag lands."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    arn = kc.create_keyspace(keyspaceName=ks_name)["resourceArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    base_tags = [{"key": f"k{i}", "value": "v"} for i in range(48)]
    _tag_resource_when_ready(kc, arn, base_tags)

    overflow_tags = [{"key": f"overflow{i}", "value": "v"} for i in range(3)]
    code, message = _error(lambda: kc.tag_resource(resourceArn=arn, tags=overflow_tags))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "Tag count exceed the imposed limit, The resultant tag set must not have more than 50 user tags."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: only the original 48 tags exist, none of the overflow tags landed
    current_keys = {t["key"] for t in _list_all_tags(kc, arn)}
    assert len(current_keys) == 48, f"expected 48 tags after rejected overflow, got {len(current_keys)}"
    assert not any(k.startswith("overflow") for k in current_keys), (
        f"an overflow tag landed despite the rejection: {sorted(current_keys)}")

    # positive control: tagging up to (but not past) the limit still succeeds
    control_tags = [{"key": f"ctrl{i}", "value": "v"} for i in range(2)]
    kc.tag_resource(resourceArn=arn, tags=control_tags)
    final_keys = {t["key"] for t in _list_all_tags(kc, arn)}
    assert len(final_keys) == 50, f"expected 50 tags after the in-bounds control, got {len(final_keys)}"
    assert "ctrl0" in final_keys and "ctrl1" in final_keys, (
        f"control tags missing from {sorted(final_keys)}")


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_resource_when_ready(kc, arn: str, tags: list, timeout_s: float = 90.0) -> None:
    """TagResource right after CreateKeyspace can transiently 404 until the keyspace is
    visible; retry only that specific transient condition."""
    import time
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.tag_resource(resourceArn=arn, tags=tags)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _list_all_tags(kc, arn: str) -> list[dict]:
    tags: list[dict] = []
    token = None
    while True:
        kwargs = {"resourceArn": arn}
        if token:
            kwargs["nextToken"] = token
        resp = kc.list_tags_for_resource(**kwargs)
        tags.extend(resp.get("tags", []))
        token = resp.get("nextToken")
        if not token:
            return tags


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

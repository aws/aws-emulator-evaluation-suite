"""tag-resource-invalid-key-format-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-key-format-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a key containing '!' (outside the modeled TagKey pattern) is rejected with
    BadRequestException and its exact message and never appears in ListTagsForResource, while a valid
    key on the same resource is applied."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-tagkey-")
    rum.create_app_monitor(Name=name, Domain="localhost")
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    arn = _app_monitor_arn(ctx, name)

    bad_key = "bad!key"  # '!' falls outside the allowed tag charset
    err = _client_error(lambda: rum.tag_resource(ResourceArn=arn, Tags={bad_key: "value"}))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err!r}"
    expected_message = (
        "Tags can only contain letters, numbers, spaces, and the following special characters: "
        "_ . : / = + - @"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absence: the rejected key never persisted.
    after_bad = rum.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    assert bad_key not in after_bad, f"expected {bad_key!r} absent, got tags {after_bad!r}"

    # Positive control: a valid key on the same resource is accepted.
    good_key = "Environment"
    rum.tag_resource(ResourceArn=arn, Tags={good_key: "staging"})
    after_good = rum.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    assert after_good.get(good_key) == "staging", f"expected {good_key!r}='staging', got {after_good.get(good_key)!r}"
    assert bad_key not in after_good, f"expected {bad_key!r} still absent, got tags {after_good!r}"


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _app_monitor_arn(ctx, name: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

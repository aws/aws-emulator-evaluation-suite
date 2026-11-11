"""tag-resource-invalid-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-key-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a tag key that uses the reserved "aws:" prefix (disallowed by
    the documented key pattern) fails with BadRequestException rather than being
    silently truncated, dropped, or accepted."""
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)

    # Break exactly one thing: a tag key starting with the reserved "aws:" prefix.
    err = _client_error(
        lambda: rum.tag_resource(ResourceArn=app["arn"], Tags={"aws:reserved": "value"})
    )
    assert err["Code"] == "BadRequestException", f"got {err!r}"
    expected_message = (
        "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: the rejected tag never landed.
    tags_after_reject = rum.list_tags_for_resource(ResourceArn=app["arn"])["Tags"]
    assert "aws:reserved" not in tags_after_reject, (
        f"rejected tag key 'aws:reserved' should be absent, got tags {tags_after_reject!r}"
    )

    # Positive control (same file): a well-formed tag key is accepted and persisted.
    rum.tag_resource(ResourceArn=app["arn"], Tags={"Environment": "sim2real"})
    tags_after_accept = rum.list_tags_for_resource(ResourceArn=app["arn"])["Tags"]
    assert tags_after_accept["Environment"] == "sim2real", (
        f"expected Environment=sim2real, got {tags_after_accept.get('Environment')!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    resp = rum.create_app_monitor(Name=name, **kwargs)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": resp["Id"], "arn": _app_monitor_arn(ctx, name)}


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""update-tags-for-resource-same-key-add-and-remove-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "update-tags-for-resource-same-key-add-and-remove-rejected"
GROUP = 'tags'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn() and return the (Error.Code, Error.Message) it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _tags(eb, arn):
    return {t["Key"]: t["Value"] for t in eb.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]}


def _update_tags(eb, timeout_s=60.0, interval_s=2.0, **kwargs):
    """UpdateTagsForResource that waits out a still-running tag workflow on the same resource.

    Elastic Beanstalk applies tag updates as an asynchronous workflow and refuses an overlapping
    one with OperationInProgressFailure; the bounded wait raises once the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eb.update_tags_for_resource(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "OperationInProgressFailure":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"a tag workflow on {kwargs.get('ResourceArn')!r} was still in progress after "
                    f"{timeout_s}s: {exc}"
                ) from exc
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTagsForResource refuses adding and removing the same key and leaves tags unchanged,
    raises ResourceNotFoundException for a missing application, and removes only the named key."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    arn = eb.create_application(ApplicationName=app_name)["Application"]["ApplicationArn"]
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    _update_tags(
        eb,
        ResourceArn=arn,
        TagsToAdd=[
            {"Key": "sim2real-keep-a", "Value": "a"},
            {"Key": "sim2real-keep-b", "Value": "b"},
            {"Key": "sim2real-contested", "Value": "original"},
        ],
    )
    baseline = _tags(eb, arn)
    for key, value in (
        ("sim2real-keep-a", "a"),
        ("sim2real-keep-b", "b"),
        ("sim2real-contested", "original"),
    ):
        assert baseline.get(key) == value, (
            f"tag {key!r} must be readable as {value!r} after UpdateTagsForResource, got {baseline!r}"
        )

    code, message = _err(
        lambda: eb.update_tags_for_resource(
            ResourceArn=arn,
            TagsToAdd=[{"Key": "sim2real-contested", "Value": "rewritten"}],
            TagsToRemove=["sim2real-contested"],
        )
    )
    # InvalidParameterValue is not a modeled error shape on UpdateTagsForResource; pinned from AWS.
    assert code == "InvalidParameterValue", (
        f"UpdateTagsForResource naming the same key in TagsToAdd and TagsToRemove is "
        f"self-contradictory and must be refused with InvalidParameterValue, got {code!r}"
    )
    expected_message = "A tag with the same key can't be added and removed in a single operation."
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    after_refusal = _tags(eb, arn)
    assert after_refusal == baseline, (
        f"a refused UpdateTagsForResource must leave the tag set byte-identical; expected "
        f"{baseline!r}, got {after_refusal!r}"
    )

    missing_arn = arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("sim2real-behav-eb-absent-")
    code, message = _err(
        lambda: eb.update_tags_for_resource(
            ResourceArn=missing_arn, TagsToAdd=[{"Key": "sim2real-x", "Value": "y"}]
        )
    )
    assert code == "ResourceNotFoundException", (
        f"UpdateTagsForResource against an application that does not exist must raise "
        f"ResourceNotFoundException, got {code!r} for {missing_arn!r}"
    )
    expected_message = f"Resource not found for ARN '{missing_arn}'."
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    _update_tags(eb, ResourceArn=arn, TagsToRemove=["sim2real-contested"])
    remaining = _tags(eb, arn)
    assert "sim2real-contested" not in remaining, (
        f"the removed key must be gone, got {remaining!r}"
    )
    assert remaining.get("sim2real-keep-a") == "a", (
        f"removing one key must not disturb its siblings; sim2real-keep-a is missing or changed in "
        f"{remaining!r} — an emulator treating UpdateTagsForResource as a whole-set replace has been "
        f"caught"
    )
    assert remaining.get("sim2real-keep-b") == "b", remaining

    # Removing a key that is not present is a no-op, not an error, and disturbs nothing.
    _update_tags(eb, ResourceArn=arn, TagsToRemove=["sim2real-never-existed"])
    assert _tags(eb, arn) == remaining, (
        f"removing an absent key must be a no-op; the tag set changed from {remaining!r} to "
        f"{_tags(eb, arn)!r}"
    )

    # An add after the refusal takes effect, proving the resource is still writable.
    _update_tags(
        eb,
        ResourceArn=arn, TagsToAdd=[{"Key": "sim2real-contested", "Value": "final"}]
    )
    assert _tags(eb, arn).get("sim2real-contested") == "final", (
        f"the application must still be taggable after the refused request, got {_tags(eb, arn)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

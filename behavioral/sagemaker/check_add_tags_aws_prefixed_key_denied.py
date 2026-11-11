"""add-tags-aws-prefixed-key-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-tags-aws-prefixed-key-denied"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTags with a key prefixed 'aws:' is rejected as a reserved namespace, not silently stored."""
    sm = ctx.client("sagemaker")

    context_name = ctx.unique_name("sim2real-behav-ctx-")
    context_arn = sm.create_context(
        ContextName=context_name,
        Source={"SourceUri": "sim2real://behavioral/context"},
        ContextType="Endpoint",
    )["ContextArn"]
    ctx.on_cleanup(lambda: sm.delete_context(ContextName=context_name))

    err = _client_error(lambda: sm.add_tags(
        ResourceArn=context_arn,
        Tags=[{"Key": "aws:sim2real-reserved", "Value": "blocked"}],
    ))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    expected_message = "System prefix 'aws:' reserved for AWS usage in tag key: aws:sim2real-reserved"
    assert err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # effect absent: the reserved-namespace tag was not stored
    tags = sm.list_tags(ResourceArn=context_arn)["Tags"]
    assert not any(t["Key"] == "aws:sim2real-reserved" for t in tags), (
        f"reserved-namespace tag persisted despite rejection: {tags}"
    )

    # positive control: a normal, non-reserved tag key is accepted
    sm.add_tags(ResourceArn=context_arn, Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}])
    tags_after = sm.list_tags(ResourceArn=context_arn)["Tags"]
    assert any(t["Key"] == "sim2real-owner" and t["Value"] == "behavioral-suite" for t in tags_after), (
        f"expected sim2real-owner=behavioral-suite in {tags_after}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

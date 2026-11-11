"""context-create-describe-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "context-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A lineage Context's properties persist across create->describe, and after delete the
    resource is both unreadable (404 on describe) and unusable (404 on a mutation by name)."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-context-")
    source_uri = f"s3://sim2real-behav-bucket/{name}"

    created = sm.create_context(
        ContextName=name,
        Source={"SourceUri": source_uri, "SourceType": "Endpoint"},
        ContextType="Endpoint",
        Description="sim2real behavioral fidelity check context",
        Properties={"env": "test"},
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _delete_context_best_effort(sm, name))

    described = sm.describe_context(ContextName=name)
    assert described["ContextArn"] == created["ContextArn"], (
        f"expected describe ContextArn to match the create response, "
        f"got {described['ContextArn']!r} vs created {created['ContextArn']!r}"
    )
    assert described["Source"]["SourceUri"] == source_uri, (
        f"expected Source.SourceUri {source_uri!r}, got {described['Source']['SourceUri']!r}"
    )
    assert described["Source"]["SourceType"] == "Endpoint", (
        f"expected Source.SourceType 'Endpoint', got {described['Source']['SourceType']!r}"
    )
    assert described["ContextType"] == "Endpoint", (
        f"expected ContextType 'Endpoint', got {described['ContextType']!r}"
    )
    assert described["Properties"] == {"env": "test"}, (
        f"expected Properties {{'env': 'test'}}, got {described['Properties']!r}"
    )

    sm.delete_context(ContextName=name)

    code, message = _error(lambda: sm.describe_context(ContextName=name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected_message = f"Context 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:context/{name}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: sm.update_context(ContextName=name, Description="post-delete mutation should fail")
    )
    assert update_code == "ResourceNotFound", (
        f"expected a mutation (UpdateContext) against a deleted context to fail with "
        f"ResourceNotFound, got {update_code}"
    )
    expected_update_message = f"Context 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:context/{name}' does not exist."
    assert update_message == expected_update_message, (
        f"expected message {expected_update_message!r}, got {update_message!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_context_best_effort(sm, name):
    try:
        sm.delete_context(ContextName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

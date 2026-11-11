"""context-lifecycle-create-describe-delete."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "context-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Context transitions from created to describable to 404 after delete."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-context-")

    created = sm.create_context(
        ContextName=name,
        Source={"SourceUri": f"s3://sim2real-lineage-bucket/{name}", "SourceType": "Custom"},
        ContextType="Endpoint",
        Description="sim2real behavioral check context",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    arn = created["ContextArn"]
    ctx.on_cleanup(lambda: _delete_context_ignore(sm, name))

    desc = sm.describe_context(ContextName=name)
    assert desc["ContextArn"] == arn, f"expected ContextArn {arn}, got {desc['ContextArn']}"
    assert desc["ContextName"] == name, f"expected ContextName {name}, got {desc['ContextName']}"
    assert desc["ContextType"] == "Endpoint", f"expected ContextType Endpoint, got {desc['ContextType']}"

    sm.delete_context(ContextName=name)

    code, message = _error(lambda: sm.describe_context(ContextName=name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected_message = f"Context 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:context/{name}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_context_ignore(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_context(ContextName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

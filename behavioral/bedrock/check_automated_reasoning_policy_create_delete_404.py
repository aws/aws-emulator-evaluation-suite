"""automated-reasoning-policy-create-delete-404."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "automated-reasoning-policy-create-delete-404"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created automated reasoning policy is returned by GetAutomatedReasoningPolicy; after
    DeleteAutomatedReasoningPolicy, Get returns ResourceNotFoundException ('Policy does not exist')
    and a second Delete ResourceNotFoundException ('Policy was not found').
    """
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-arpolicy-")

    create_resp = bedrock.create_automated_reasoning_policy(name=name)
    policy_arn = create_resp["policyArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(bedrock, policy_arn))

    assert create_resp["name"] == name, (
        f"expected created policy name {name!r}, got {create_resp['name']!r}"
    )
    assert create_resp.get("version"), (
        f"expected CreateAutomatedReasoningPolicy to report a non-empty version, got {create_resp.get('version')!r}"
    )

    got = bedrock.get_automated_reasoning_policy(policyArn=policy_arn)
    assert got["name"] == name, f"expected GetAutomatedReasoningPolicy name {name!r}, got {got['name']!r}"
    assert got["version"] == create_resp["version"], (
        f"expected GetAutomatedReasoningPolicy version {create_resp['version']!r}, got {got['version']!r}"
    )

    bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)

    code, message = _error(lambda: bedrock.get_automated_reasoning_policy(policyArn=policy_arn))
    assert code == "ResourceNotFoundException", (
        f"expected a deleted policy's Get to raise ResourceNotFoundException, got {code!r}"
    )
    assert message == "Policy does not exist", (
        f"expected a deleted policy's Get message 'Policy does not exist', got {message!r}"
    )

    # mutation on the dead id: a second delete of the same ARN must also be rejected,
    # not silently accepted as a no-op.
    second_delete_code, second_delete_message = _error(
        lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a second Delete of an already-deleted policy to raise ResourceNotFoundException, "
        f"got {second_delete_code!r}"
    )
    assert second_delete_message == "Policy was not found", (
        f"expected a second Delete message 'Policy was not found', got {second_delete_message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(bedrock, policy_arn):
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

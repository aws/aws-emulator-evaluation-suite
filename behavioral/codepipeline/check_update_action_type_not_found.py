"""update-action-type-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-action-type-not-found"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']

def _account_id(ctx) -> str:
    """The target's account id, the same source on every target."""
    return ctx.account

def _lambda_executor(ctx) -> dict:
    return {
        "configuration": {
            "lambdaExecutorConfiguration": {
                "lambdaFunctionArn": (
                    f"arn:aws:lambda:{ctx.region}:{_account_id(ctx)}:"
                    "function:sim2real-behav-none"
                )
            }
        },
        "type": "Lambda",
    }

def _custom_providers(client) -> set[str]:
    providers: set[str] = set()
    paginator = client.get_paginator("list_action_types")
    for page in paginator.paginate(actionOwnerFilter="Custom"):
        for at in page.get("actionTypes", []):
            providers.add(at["id"]["provider"])
    return providers

def _update_action_type(client, ctx, owner: str, category: str, provider: str, version: str):
    """Raises on unexpected success; returns (code, message) on a ClientError."""
    client.update_action_type(actionType={
        "id": {"category": category, "owner": owner, "provider": provider, "version": version},
        "executor": _lambda_executor(ctx),
        "inputArtifactDetails": {"minimumCount": 0, "maximumCount": 1},
        "outputArtifactDetails": {"minimumCount": 0, "maximumCount": 1},
    })

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """In a non-partner account UpdateActionType refuses both a nonexistent ThirdParty id and the
    real AWS-owned Approval/AWS/Manual/1 with ActionTypeNotFoundException, creating nothing, while
    CreateCustomActionType works."""
    ev = ctx.client("codepipeline")

    # Positive control: an operation this account can genuinely complete.
    category, version = "Build", "1"
    provider = ctx.unique_name("sim2real-behav-ca-upd-")
    ev.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: ev.delete_custom_action_type(category=category, provider=provider, version=version)
    )
    assert provider in _custom_providers(ev), f"{provider} missing from ListActionTypes after create"

    # The specific refusal, on a genuinely nonexistent id.
    missing_provider = ctx.unique_name("sim2real-behav-ca-none-")
    try:
        _update_action_type(ev, ctx, "ThirdParty", "Build", missing_provider, "1")
        raise AssertionError(
            f"UpdateActionType unexpectedly succeeded for owner=ThirdParty "
            f"provider={missing_provider}, which was never created"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    assert code == "ActionTypeNotFoundException", (code, message)
    assert message == _not_found_message("ThirdParty", "Build", missing_provider, "1"), message

    # The identical refusal for a real, currently-listed AWS-owned id --
    # proving the gate is account entitlement, not existence.
    try:
        _update_action_type(ev, ctx, "AWS", "Approval", "Manual", "1")
        raise AssertionError(
            "UpdateActionType unexpectedly succeeded for the real, AWS-owned "
            "Approval/AWS/Manual/1 action type"
        )
    except ClientError as exc:
        real_code = exc.response.get("Error", {}).get("Code")
        real_message = exc.response.get("Error", {}).get("Message", "")
    assert real_code == "ActionTypeNotFoundException", (real_code, real_message)
    assert real_message == _not_found_message("AWS", "Approval", "Manual", "1"), real_message

    # Effect-absent: an independent read confirms the fabricated provider
    # was never created, at neither the owner it was rejected under nor Custom.
    for owner in ("ThirdParty", "Custom"):
        for at in ev.list_action_types(actionOwnerFilter=owner).get("actionTypes", []):
            assert at["id"]["provider"] != missing_provider, (owner, at)


def _not_found_message(owner: str, category: str, provider: str, version: str) -> str:
    """AWS's exact ActionTypeNotFoundException text for UpdateActionType."""
    return (
        f"An action type with owner=[{owner}], category=[{category}], provider=[{provider}] "
        f"and version=[{version}] doesn't exist. To create an action type, contact the "
        "CodePipeline service team."
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

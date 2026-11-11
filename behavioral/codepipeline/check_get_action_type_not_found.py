"""get-action-type-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-action-type-not-found"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetActionType for an unknown ThirdParty action type fails with ActionTypeNotFoundException and its exact
    message, and the provider is absent from ListActionTypes, while a created Custom action type is listed.
    """
    ev = ctx.client("codepipeline")

    control_provider = ctx.unique_name("sim2real-ca-ok-")
    ev.create_custom_action_type(
        category="Build",
        provider=control_provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: ev.delete_custom_action_type(category="Build", provider=control_provider, version="1")
    )

    def _providers(owner_filter: str) -> set[str]:
        providers: set[str] = set()
        paginator = ev.get_paginator("list_action_types")
        for page in paginator.paginate(actionOwnerFilter=owner_filter):
            for at in page.get("actionTypes", []):
                providers.add(at["id"]["provider"])
        return providers

    assert control_provider in _providers("Custom"), (
        f"{control_provider} missing from ListActionTypes(Custom) right after creation -- "
        "account/credentials are not healthy for codepipeline"
    )

    absent_provider = ctx.unique_name("sim2real-behav-ca-none-")
    try:
        result = ev.get_action_type(category='Build', owner='ThirdParty', provider=absent_provider, version='1')
    except ClientError as exc:
        refusal = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(f"expected ActionTypeNotFoundException, but GetActionType succeeded: {result!r}")
    assert refusal == (
        "ActionTypeNotFoundException",
        f"Action type with owner=ThirdParty, category=Build, provider={absent_provider} and version=1 does not exist.",
    ), refusal

    assert absent_provider not in _providers("ThirdParty"), (
        f"{absent_provider} unexpectedly present in ListActionTypes(ThirdParty)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""workload-access-token-for-user-id-ttl-scoped."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workload-access-token-for-user-id-ttl-scoped"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two GetWorkloadAccessTokenForUserId calls for the same workload and userId mint two distinct
    tokens, and each is accepted at once by GetResourceApiKey (ResourceNotFoundException for an
    unknown provider).
    """
    control = ctx.client("bedrock-agentcore-control")
    agentcore = ctx.client("bedrock-agentcore")

    workload_name = ("simreal-wat-uid-" + uuid.uuid4().hex)[:60]
    control.create_workload_identity(name=workload_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(
        lambda: _safe(lambda: control.delete_workload_identity(name=workload_name))
    )

    user_id = "sim2real-user-1"
    token_1 = agentcore.get_workload_access_token_for_user_id(
        workloadName=workload_name, userId=user_id
    )["workloadAccessToken"]
    token_2 = agentcore.get_workload_access_token_for_user_id(
        workloadName=workload_name, userId=user_id
    )["workloadAccessToken"]

    assert token_1 != token_2, "expected two independent calls to mint distinct tokens"

    for token in (token_1, token_2):
        code, message = _error(
            lambda t=token: agentcore.get_resource_api_key(
                workloadIdentityToken=t,
                resourceCredentialProviderName="sim2real-nonexistent-provider",
            )
        )
        assert code == "ResourceNotFoundException", (
            f"expected a freshly minted token to be accepted, got {code}"
        )
        assert message == "Resource Credential Provider not found", (
            f"expected the exact provider-not-found message, got {message!r}"
        )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

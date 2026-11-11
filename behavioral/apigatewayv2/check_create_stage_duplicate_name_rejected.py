"""create-stage-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stage-duplicate-name-rejected"
GROUP = "stages"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStage with a name the API already has is refused, and the existing stage keeps its own
    description and variables; the same name on a second API is accepted (names are unique per API).
    """
    agw = ctx.client("apigatewayv2")
    api_ids = []
    for _ in range(2):
        api_id = agw.create_api(
            Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
        )["ApiId"]
        ctx.on_cleanup(lambda a=api_id: agw.delete_api(ApiId=a))
        api_ids.append(api_id)
    first, second = api_ids
    agw.create_stage(
        ApiId=first, StageName="prod", Description="original", StageVariables={"color": "blue"}
    )

    code, message = _error(lambda: agw.create_stage(
        ApiId=first, StageName="prod", Description="duplicate", StageVariables={"color": "red"}
    ))
    assert code == "ConflictException", (
        f"CreateStage with an existing name: expected ConflictException, got {code}: {message!r}"
    )
    assert message == "Stage already exists", f"unexpected message {message!r}"
    kept = agw.get_stage(ApiId=first, StageName="prod")
    assert (kept.get("Description"), kept.get("StageVariables")) == ("original", {"color": "blue"}), (
        f"the refused CreateStage changed the existing stage: {kept!r}"
    )

    other = agw.create_stage(ApiId=second, StageName="prod", Description="other api")
    assert other["StageName"] == "prod", f"the same name on another API was not created: {other!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


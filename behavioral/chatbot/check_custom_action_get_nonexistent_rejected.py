"""custom-action-get-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-action-get-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCustomAction on a well-formed CustomActionArn that was never created fails with UnauthorizedException
    "Unauthorized", not ResourceNotFoundException, while GetCustomAction on an action created in the same run
    returns that action."""
    chatbot = ctx.client("chatbot")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    fake_arn = f"arn:aws:chatbot:{region}:{account_id}:custom-action/sim2real-never-created-action"

    code, message = _error(lambda: chatbot.get_custom_action(CustomActionArn=fake_arn))
    assert code == "UnauthorizedException", f"expected UnauthorizedException, got code={code!r}"
    assert message == "Unauthorized", f"unexpected message={message!r}"

    real_name = ctx.unique_name("sim2realreal").replace("-", "")[:64]
    real_arn = chatbot.create_custom_action(
        ActionName=real_name,
        Definition={"CommandText": "echo real"},
        Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, real_arn))

    got = chatbot.get_custom_action(CustomActionArn=real_arn)["CustomAction"]
    assert got["CustomActionArn"] == real_arn, f"expected {real_arn!r}, got {got['CustomActionArn']!r}"


def _safe_delete(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""create-custom-action-missing-permission-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-custom-action-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomAction from a role with no permissions fails with AccessDeniedException "User: <session arn> is
    not authorized to perform: chatbot:CreateCustomAction ... because no identity-based policy allows ...",
    creates no action, and the same call with the caller's own credentials succeeds."""
    chatbot = ctx.client("chatbot")
    iam = ctx.client("iam")
    account_id = ctx.account

    role_name = ctx.unique_name("sim2real-noperm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "env", "Value": "sim2real"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("sim2real-session-")[:64]
    restricted_chatbot = _assume_role_client(ctx, role_arn, session_name, "chatbot")

    action_name = ctx.unique_name("sim2realdenied").replace("-", "")[:64]
    # Registered before the call: if a wrongly-permissive target actually creates
    # this action, it is still deleted even though the assertion below fails.
    ctx.on_cleanup(lambda: _cleanup_by_name(ctx, action_name))
    code, message = _error(
        lambda: restricted_chatbot.create_custom_action(
            ActionName=action_name,
            Definition={"CommandText": "echo denied"},
            Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
        )
    )
    assert code == "AccessDeniedException", f"unexpected code={code!r}"
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{session_name} is not authorized "
        f"to perform: chatbot:CreateCustomAction on resource: "
        f"arn:aws:chatbot::{ctx.account}:custom-action/{action_name} because no identity-based "
        f"policy allows the chatbot:CreateCustomAction action"
    )
    assert message == expected, f"unexpected message={message!r}"

    # Effect absent: no custom action was created under that name.
    all_actions_arns = _list_all_custom_actions(ctx)
    assert not any(action_name in arn for arn in all_actions_arns), (
        f"expected no action named {action_name!r} after denied create, found one in {all_actions_arns!r}"
    )

    # Positive control: the caller's own (permitted) identity can still create one.
    control_arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2realcontrol").replace("-", "")[:64],
        Definition={"CommandText": "echo control"},
        Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, control_arn))
    got = chatbot.get_custom_action(CustomActionArn=control_arn)["CustomAction"]
    assert got["CustomActionArn"] == control_arn, (
        f"expected get_custom_action to echo back {control_arn!r}, got {got['CustomActionArn']!r}"
    )


def _assume_role_client(ctx, role_arn: str, session_name: str, service: str):
    sts = ctx.client("sts")

    deadline = time.monotonic() + 20.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except Exception as exc:  # noqa: BLE001 - IAM role propagation retry
            last_exc = exc
            time.sleep(1.5)
    raise AssertionError(f"could not assume newly created role in time: {last_exc}")


def _list_all_custom_actions(ctx) -> list[str]:
    chatbot = ctx.client("chatbot")
    out: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = chatbot.list_custom_actions(**kwargs)
        out.extend(resp.get("CustomActions", []))
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _safe_delete(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cleanup_by_name(ctx, action_name: str) -> None:
    for arn in _list_all_custom_actions(ctx):
        if action_name in arn:
            _safe_delete(ctx, arn)


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

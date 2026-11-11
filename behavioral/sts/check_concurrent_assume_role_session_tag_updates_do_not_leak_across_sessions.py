"""concurrent-assume-role-session-tag-updates-do-not-leak-across-sessions."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-assume-role-session-tag-updates-do-not-leak-across-sessions"
GROUP = "concurrency"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent red- and blue-tagged AssumeRole sessions chained into a role whose trust policy
    requires aws:PrincipalTag/color=red each get the outcome of their OWN tag: red sessions
    assume it, blue ones get AccessDenied."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    r1_name = ctx.unique_name("sim2real-behav-tagsrc-")
    r2_name = ctx.unique_name("sim2real-behav-taggate-")

    r1_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }],
    }
    r1_arn = iam.create_role(
        RoleName=r1_name,
        AssumeRolePolicyDocument=json.dumps(r1_trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=r1_name))

    iam.put_role_policy(
        RoleName=r1_name,
        PolicyName="allow-assume-r2",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=r1_name, PolicyName="allow-assume-r2"))

    r2_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": r1_arn},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:PrincipalTag/color": "red"}},
        }],
    }
    # A just-created role's ARN can take a few seconds to become recognized as a valid
    # principal in another role's trust policy (IAM eventual consistency); retry.
    r2_arn = None
    create_deadline = time.monotonic() + 30
    last_exc = None
    while time.monotonic() < create_deadline:
        try:
            r2_arn = iam.create_role(
                RoleName=r2_name,
                AssumeRolePolicyDocument=json.dumps(r2_trust),
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )["Role"]["Arn"]
            break
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument":
                raise
            time.sleep(3)
    assert r2_arn is not None, f"could not create role referencing r1 as principal: {last_exc}"
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=r2_name))

    def _chain(tag_value):
        session_name = ctx.unique_name("s1-")[:64]
        try:
            outer = sts.assume_role(
                RoleArn=r1_arn,
                RoleSessionName=session_name,
                Tags=[{"Key": "color", "Value": tag_value}],
            )
        except ClientError as exc:
            return {
                "outer_ok": False,
                "outer_error": exc.response["Error"]["Code"],
                "inner_ok": None,
                "inner_error": None,
            }
        inner_client = _client_from_creds(ctx, sts, outer["Credentials"])
        try:
            inner_client.assume_role(RoleArn=r2_arn, RoleSessionName=ctx.unique_name("s2-")[:64])
            return {"outer_ok": True, "outer_error": None, "inner_ok": True, "inner_error": None}
        except ClientError as exc:
            return {
                "outer_ok": True,
                "outer_error": None,
                "inner_ok": False,
                "inner_error": exc.response["Error"]["Code"],
                "inner_message": exc.response["Error"].get("Message"),
                "outer_arn": outer["AssumedRoleUser"]["Arn"],
            }

    # Trust-policy propagation is inconsistent across backend nodes for a few seconds after the
    # first success, so require several back-to-back successful chains before racing.
    stability_target = 3
    deadline = time.monotonic() + 90
    warm = None
    consecutive = 0
    while time.monotonic() < deadline and consecutive < stability_target:
        warm = _chain("red")
        if warm["outer_ok"] and warm["inner_ok"]:
            consecutive += 1
        else:
            consecutive = 0
        time.sleep(2)
    assert warm is not None and consecutive >= stability_target, (
        f"tag-gated chain never became stably usable ({consecutive}/{stability_target} "
        f"consecutive successes): {warm}"
    )

    tasks = ["red", "blue", "red", "blue", "red", "blue"]
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        results = list(pool.map(_chain, tasks))

    for tag_value, result in zip(tasks, results):
        assert result["outer_ok"] is True, f"AssumeRole on the tag-source role failed: {result}"
        if tag_value == "red":
            assert result["inner_ok"] is True, f"red-tagged session was wrongly denied: {result}"
        else:
            assert result["inner_ok"] is False, f"blue-tagged session leaked the red grant: {result}"
            assert result["inner_error"] == "AccessDenied", (
                f"expected AccessDenied for a blue-tagged session, got {result['inner_error']!r}"
            )
            assert result["inner_message"] == (
                f"User: {result['outer_arn']} is not authorized to perform: sts:AssumeRole "
                f"on resource: {r2_arn}"
            ), result


def _client_from_creds(ctx, base_client, creds):
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

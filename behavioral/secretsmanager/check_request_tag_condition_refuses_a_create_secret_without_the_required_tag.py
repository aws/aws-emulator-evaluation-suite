"""request-tag-condition-refuses-a-create-secret-without-the-required-tag."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-tag-condition-refuses-a-create-secret-without-the-required-tag"
GROUP = "enforcement"
SERVICES = ["secretsmanager"]

_SESSION_NAME = "sim2real-behav-tagged-creator"
_TAG_KEY = "sim2real-owner"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An identity policy allowing CreateSecret only with an aws:RequestTag condition refuses the
    role's untagged and wrong-value creates with AccessDeniedException, leaving no secret, while
    the create carrying the required tag succeeds and the secret holds exactly that tag.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]
    owner = ctx.unique_name("team-")
    prefix = ctx.unique_name("sim2real-behav-reqtag-")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:CreateSecret", "secretsmanager:TagResource"],
                "Resource": "*",
                "Condition": {"StringEquals": {f"aws:RequestTag/{_TAG_KEY}": owner}},
            }
        ],
    }
    role_arn, role_name = _create_role(ctx, iam, account_id, policy)
    as_role = _client_as(ctx, _assume(sts, role_arn))
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"

    # Positive first: once this succeeds the role's policy has propagated, so the refusals that
    # follow are evaluations of the condition rather than a not-yet-effective grant.
    good_name = prefix + "-tagged"
    created = _poll_create(
        lambda: as_role.create_secret(
            Name=good_name,
            SecretString="owned",
            Tags=[{"Key": _TAG_KEY, "Value": owner}],
        ),
        timeout_s=90.0,
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=created["ARN"], ForceDeleteWithoutRecovery=True))
    held = {t["Key"]: t["Value"] for t in sm.describe_secret(SecretId=created["ARN"]).get("Tags", [])}
    assert held == {_TAG_KEY: owner}, f"the created secret must carry exactly the required tag; got {held!r}"
    assert sm.get_secret_value(SecretId=created["ARN"])["SecretString"] == "owned", (
        "the tagged create must have stored its value"
    )

    for suffix, kwargs in (
        ("-untagged", {}),
        ("-wrongtag", {"Tags": [{"Key": _TAG_KEY, "Value": owner + "-other"}]}),
    ):
        name = prefix + suffix
        code, message = _refusal(ctx, sm, lambda n=name, kw=kwargs: as_role.create_secret(
            Name=n, SecretString="should-not-exist", **kw
        ))
        assert code == "AccessDeniedException", (
            f"CreateSecret {suffix[1:]} must be refused with AccessDeniedException; got {code!r}: {message!r}"
        )
        expected = (
            f"User: {session_arn} is not authorized to perform: secretsmanager:CreateSecret on "
            f"resource: {name} because no identity-based policy allows the "
            "secretsmanager:CreateSecret action"
        )
        assert message == expected, f"refusal message {message!r} != {expected!r}"
        absent = _describe_code(sm, name)
        assert absent == ("ResourceNotFoundException", "Secrets Manager can't find the specified secret."), (
            f"a refused CreateSecret must leave no secret named {name!r}; DescribeSecret gave {absent!r}"
        )


def _create_role(ctx, iam, account_id, policy):
    role_name = ctx.unique_name("sim2real-behav-reqtag-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="creator", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="creator"))
    return role["Role"]["Arn"], role_name


def _assume(sts, role_arn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"assume-role never succeeded (trust policy propagation?): {last_err}")


def _client_as(ctx, creds):
    return ctx.client(
        "secretsmanager",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll_create(fn, *, timeout_s, interval_s=3.0):
    """The first create the role is entitled to make, retried only while IAM propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "UnrecognizedClientException", "InvalidClientTokenId"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the tagged create was never permitted within {timeout_s}s: {exc}")
            time.sleep(interval_s)


def _refusal(ctx, sm, fn):
    """(code, message) of the refused call; an unexpected success registers the delete of what it
    created, then fails."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=result["ARN"], ForceDeleteWithoutRecovery=True))
    raise AssertionError(f"expected the create to be refused, but it succeeded: {result!r}")


def _describe_code(sm, name):
    try:
        sm.describe_secret(SecretId=name)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "<exists>", None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

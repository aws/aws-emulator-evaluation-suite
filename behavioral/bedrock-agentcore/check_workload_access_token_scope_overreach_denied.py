"""workload-access-token-scope-overreach-denied."""
from __future__ import annotations

import json
import random
import string
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workload-access-token-scope-overreach-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal granted GetWorkloadAccessToken on one workload identity is refused with
    AccessDeniedException naming another existing workload identity, while it mints a token for its
    own: the grant is enforced per workload identity.
    """
    control = ctx.client("bedrock-agentcore-control")
    account_id = _account_id(ctx)

    owned_name = ctx.unique_name("sim2real-behav-wi-a-")
    other_name = ctx.unique_name("sim2real-behav-wi-b-")

    control.create_workload_identity(name=owned_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe(lambda: control.delete_workload_identity(name=owned_name)))
    control.create_workload_identity(name=other_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe(lambda: control.delete_workload_identity(name=other_name)))

    # Directory id is service-assigned and not exposed to GetWorkloadAccessToken callers. The
    # operation authorizes against BOTH the workload-identity-directory resource ("default")
    # AND the specific workload-identity resource, so the grant must cover both resource
    # types or the call is denied even for the principal's own identity.
    directory_arn = (
        f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:"
        f"workload-identity-directory/default"
    )
    owned_resource = (
        f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:"
        f"workload-identity-directory/default/workload-identity/{owned_name}"
    )

    restricted, role_name = _assume_role_client(
        ctx,
        "bedrock-agentcore",
        [
            {
                "Effect": "Allow",
                "Action": "bedrock-agentcore:GetWorkloadAccessToken",
                "Resource": [owned_resource, directory_arn],
            }
        ],
    )

    code, message = _error(
        lambda: _settled(lambda: restricted.get_workload_access_token(workloadName=other_name))
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    other_resource = (
        f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:"
        f"workload-identity-directory/default/workload-identity/{other_name}"
    )
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav-session is not "
        "authorized to perform: bedrock-agentcore:GetWorkloadAccessToken on resource: "
        f"{other_resource} because no identity-based policy allows the "
        "bedrock-agentcore:GetWorkloadAccessToken action"
    ), f"expected the exact identity-policy denial message, got {message!r}"

    control_resp = _settled(lambda: restricted.get_workload_access_token(workloadName=owned_name))
    assert control_resp["workloadAccessToken"], (
        "positive control: the same principal minting a token for its own permitted, "
        "really-existing workload identity should succeed and return a non-empty token"
    )


def _rand_suffix(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# A session token AssumeRole just minted can be refused by the service for a few seconds.
_TOKEN_NOT_YET_VALID = "The security token included in the request is invalid."


def _settled(fn, *, timeout_s=60.0, interval_s=3.0):
    """fn() once the service accepts the freshly minted session token. Only that refusal is
    retried, within a bounded window; any other outcome, and the last refusal, is returned or
    raised as is."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"].get("Message") != _TOKEN_NOT_YET_VALID:
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _assume_role_client(ctx, service: str, statements: list[dict[str, Any]]):
    """Create an IAM role whose inline policy is exactly `statements`, assume it, and return a
    client for `service` backed by the resulting temporary credentials, and the role name."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = _account_id(ctx)
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
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
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "inline-scope"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    deadline = time.monotonic() + 30.0
    creds = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-behav-session"
            )["Credentials"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(1.5)
    if creds is None:
        raise AssertionError(f"role never became assumable: {last_err}")

    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

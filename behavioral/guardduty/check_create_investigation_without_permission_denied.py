"""create-investigation-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-investigation-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateInvestigation without the required IAM permission is rejected with
    AccessDeniedException rather than partially executing, while a permitted caller's identical
    call still creates an investigation."""
    gd = ctx.client("guardduty")
    account_id = ctx.account

    detector_id = gd.create_detector(
        Enable=True,
        Features=[{"Name": "AI_ANALYST", "Status": "ENABLED"}],
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    baseline_prompt = "sim2real behavioral check: summarize any suspicious IAM activity."
    baseline = gd.create_investigation(DetectorId=detector_id, TriggerPrompt=baseline_prompt)
    baseline_id = baseline["InvestigationId"]
    assert baseline_id, "positive-control CreateInvestigation did not return an InvestigationId"

    role = _create_deny_role(ctx, account_id, ["guardduty:CreateInvestigation"])
    restricted_gd = _assume_role_client(ctx, role["role_arn"])

    denied_prompt = "sim2real behavioral check: this attempt must be denied."
    code, message = _error_code(
        lambda: restricted_gd.create_investigation(
            DetectorId=detector_id, TriggerPrompt=denied_prompt
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    action = "guardduty:CreateInvestigation"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role['role_name']}/{_SESSION_NAME} "
        f"is not authorized to perform: {action} on resource: "
        f"arn:aws:guardduty:{ctx.region}:{account_id}:detector/{detector_id}/investigation "
        f"with an explicit deny in an identity-based policy"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    investigations = gd.list_investigations(DetectorId=detector_id).get("Investigations", [])
    prompts = [inv.get("TriggerPrompt") for inv in investigations]
    assert denied_prompt not in prompts, "denied CreateInvestigation call still produced an investigation"
    assert baseline_prompt in prompts, "positive-control investigation is missing from ListInvestigations"


_SESSION_NAME = "sim2real-behav-session"


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


def _create_deny_role(ctx, account_id, deny_actions):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-gd-deny-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": deny_actions, "Resource": "*"}],
    }
    policy_name = "deny-inline"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return {"role_name": role_name, "role_arn": role_arn}


def _assume_role_client(ctx, role_arn):
    sts = ctx.client("sts")
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
            client = ctx.client(
                "guardduty",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
            continue
        # a fresh session can briefly be unrecognized; any other answer (the role has no
        # allow, so AccessDeniedException) means the credentials are live
        try:
            client.list_detectors()
        except ClientError as err:
            if err.response["Error"]["Code"] in ("UnrecognizedClientException", "InvalidClientTokenId"):
                last_err = err
                time.sleep(3.0)
                continue
        return client
    raise AssertionError(f"could not assume role {role_arn} in time: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

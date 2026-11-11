"""send-workflow-step-state-unauthorized-denied."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-workflow-step-state-unauthorized-denied"
GROUP = "overly-permissive"
SERVICES = ["transfer"]

_SESSION_NAME = "sim2real-behavioral-negative"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendWorkflowStepState from a principal without permission is AccessDeniedException,
    while the same bogus-ID call with full permissions is ResourceNotFoundException,
    so the denial is about the missing permission, not the IDs."""
    transfer = ctx.client("transfer")

    unauthorized_creds, role_name, account_id = _assume_unprivileged_role(ctx)
    unauthorized_transfer = ctx.client(
        "transfer",
        creds={
            "aws_access_key_id": unauthorized_creds["AccessKeyId"],
            "aws_secret_access_key": unauthorized_creds["SecretAccessKey"],
            "aws_session_token": unauthorized_creds["SessionToken"],
        },
    )

    bogus_workflow_id = "w-" + "0" * 17
    bogus_execution_id = str(uuid.uuid4())
    bogus_token = "abogustokenvalue1234567890"

    # Freshly issued role-session credentials can be unrecognised for a few seconds; wait
    # (bounded) until the service recognises them before grading the authorization refusal.
    deadline = time.monotonic() + 60
    while True:
        code, message = _err(
            lambda: unauthorized_transfer.send_workflow_step_state(
                WorkflowId=bogus_workflow_id,
                ExecutionId=bogus_execution_id,
                Token=bogus_token,
                Status="SUCCESS",
            )
        )
        if code != "UnrecognizedClientException" or time.monotonic() >= deadline:
            break
        time.sleep(3)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_denial = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: transfer:SendWorkflowStepState on resource: "
        f"arn:aws:transfer:{ctx.region}:{account_id}:workflow/{bogus_workflow_id} because no "
        f"identity-based policy allows the transfer:SendWorkflowStepState action"
    )
    assert message == expected_denial, f"unexpected AccessDeniedException message {message!r}"

    # Positive control: the same call, with full permissions, gets past IAM authz and
    # fails on domain validation instead (the workflow/execution genuinely don't exist).
    control_code, control_message = _err(
        lambda: transfer.send_workflow_step_state(
            WorkflowId=bogus_workflow_id,
            ExecutionId=bogus_execution_id,
            Token=bogus_token,
            Status="SUCCESS",
        )
    )
    assert control_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException with full permissions, got {control_code}"
    )
    assert control_message == "Unknown workflow", (
        f"unexpected ResourceNotFoundException message {control_message!r}"
    )


def _assume_unprivileged_role(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # No policy is attached, so this role has no permissions beyond the trust relationship
    # itself -- any AWS Transfer Family call it makes must be denied by IAM.
    deadline = time.monotonic() + 30
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            return creds, role_name, account_id
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"could not assume freshly created role in time: {last_exc}")


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

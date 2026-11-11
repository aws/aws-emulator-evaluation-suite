"""create-import-task-lifecycle."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "create-import-task-lifecycle"
GROUP = 'import-tasks'
SERVICES = ['logs']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateImportTask against a well-formed but nonexistent event data store, with a correctly
    permissioned role, is ResourceNotFoundException, and Describe/Cancel on an unknown importId
    are ResourceNotFoundException "No matching import found."."""
    svc = ctx.client("logs")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # CloudTrail Lake no longer accepts new customers, so a real event data store cannot be
    # created; a valid role makes the missing source the only broken variable.
    fake_event_data_store = f"arn:aws:cloudtrail:{ctx.region}:{account}:eventdatastore/{uuid.uuid4()}"

    role_name = ctx.unique_name("sim2real-behav-importrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "create-import-task-lifecycle"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "import-permissions"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "cloudtrail:GetEventDataStoreData",
                        "Resource": fake_event_data_store,
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutResourcePolicy",
                        ],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    def _try_create():
        return _error(
            lambda: svc.create_import_task(
                importSourceArn=fake_event_data_store, importRoleArn=role_arn
            )
        )

    # A just-created role/policy can take a few seconds to propagate; retry while the
    # failure looks transient rather than accepting whatever the very first attempt returns.
    deadline = time.monotonic() + 60.0
    create_code = _try_create()
    while create_code[0] in ("InvalidParameterException", "AccessDeniedException") and time.monotonic() < deadline:
        time.sleep(5.0)
        create_code = _try_create()

    # message varies: AWS relays the downstream CloudTrail error, which embeds a per-request id
    assert create_code[0] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a non-existent import source, got {create_code!r}"
    )

    fake_import_id = str(uuid.uuid4())
    code, msg = _error(
        lambda: svc.describe_import_tasks(importId=fake_import_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a non-existent importId, got {code!r} {msg!r}"
    )
    assert msg == "No matching import found.", f"unexpected DescribeImportTasks message: {msg!r}"

    code, msg = _error(
        lambda: svc.describe_import_task_batches(importId=fake_import_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a non-existent importId, got {code!r} {msg!r}"
    )
    assert msg == "No matching import found.", f"unexpected DescribeImportTaskBatches message: {msg!r}"

    code, msg = _error(lambda: svc.cancel_import_task(importId=fake_import_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a non-existent importId, got {code!r} {msg!r}"
    )
    assert msg == "No matching import found.", f"unexpected CancelImportTask message: {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

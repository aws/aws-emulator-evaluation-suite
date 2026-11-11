"""create-environment-schedulers-exceeds-max-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-environment-schedulers-exceeds-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["mwaa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEnvironment rejects Schedulers > 5 with ValidationException and creates no
    environment; a real, assumable execution role gets the request past the assume-role
    check AWS performs first, so the refusal comes from the Schedulers bound."""
    mwaa = ctx.client("mwaa")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mwaa-badsched-")

    role_name = ctx.unique_name("sim2real-mwaa-badsched-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": ["airflow.amazonaws.com", "airflow-env.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    code, message = _error_after_role_propagation(
        ctx,
        lambda: mwaa.create_environment(
            Name=name,
            ExecutionRoleArn=role_arn,
            SourceBucketArn="arn:aws:s3:::some-bucket-name",
            DagS3Path="dags",
            NetworkConfiguration={
                "SubnetIds": ["subnet-00000000000000001", "subnet-00000000000000002"],
                "SecurityGroupIds": ["sg-00000000000000001"],
            },
            Schedulers=6,
        ),
    )
    assert code == "ValidationException", f"expected ValidationException, actual_code={code!r}"
    assert message == (
        "1 validation error detected: Value '6' at 'schedulers' failed to satisfy constraint: "
        "Member must have value less than or equal to 5"
    ), f"actual_message={message!r}"

    # Effect absent: no environment record was created under that name.
    not_found_code, not_found_message = _error(lambda: mwaa.get_environment(Name=name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, actual_code={not_found_code!r}"
    )
    assert not_found_message == f"Environment {name} not found.", (
        f"actual_message={not_found_message!r}"
    )

    # Positive control: the mwaa API is not just blanket-rejecting every call.
    control = mwaa.list_environments(MaxResults=5)
    assert "Environments" in control, f"expected an Environments key, actual={control!r}"


# ===== helpers =====


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises:
    accepting a call AWS refuses is reported as such, not as a bare code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _error_after_role_propagation(ctx, fn, timeout_s=120.0):
    """``_error(fn)``, retried every 2 s while the refusal names the just-created role (IAM
    propagation is eventually consistent), to a deadline capped by the time left."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        code, message = _error(fn)
        role_refused = code in ("ValidationException", "AccessDeniedException") and "role" in (message or "").lower()
        if not role_refused or time.monotonic() >= deadline:
            return code, message
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


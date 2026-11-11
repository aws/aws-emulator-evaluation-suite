"""op-contract-generateServiceLastAccessedDetails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-generateServiceLastAccessedDetails"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GenerateServiceLastAccessedDetails for a real entity ARN returns a
    36-character JobId whose job reaches COMPLETED, and a nonexistent ARN fails
    with NoSuchEntity and its exact message."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-slad-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    gen = iam.generate_service_last_accessed_details(Arn=role["Arn"])
    job_id = gen["JobId"]
    assert len(job_id) == 36

    status = _poll_job_status(iam, job_id, timeout_s=60.0)
    assert status == "COMPLETED", f"expected the job to complete, got {status!r}"

    bogus_arn = f"arn:aws:iam::{account_id}:role/{role_name}-definitely-does-not-exist"
    code, message = _error(lambda: iam.generate_service_last_accessed_details(Arn=bogus_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code!r}"
    expected = f"ARN {bogus_arn} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_job_status(iam, job_id: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = iam.get_service_last_accessed_details(JobId=job_id)
        status = resp["JobStatus"]
        if status in {"COMPLETED", "FAILED"}:
            return status
        time.sleep(2.0)
    raise TimeoutError(f"job {job_id} did not reach a terminal status within {timeout_s}s (last: {status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""get-service-last-accessed-details-contract."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-service-last-accessed-details-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetServiceLastAccessedDetails: async job success-path + NoSuchEntity boundary."""
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-gslad-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    gen = iam.generate_service_last_accessed_details(Arn=role_arn)
    job_id = gen["JobId"]

    result = _poll_until(
        lambda: iam.get_service_last_accessed_details(JobId=job_id),
        lambda r: r["JobStatus"] in ("COMPLETED", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert result["JobStatus"] == "COMPLETED", f"job did not complete: {result}"
    assert result["JobType"] == "SERVICE_LEVEL", (
        f"expected default-granularity job type SERVICE_LEVEL, got {result.get('JobType')!r}"
    )
    assert isinstance(result["ServicesLastAccessed"], list), (
        f"expected ServicesLastAccessed to be a list, got {result['ServicesLastAccessed']!r}"
    )

    unknown_job = "00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: iam.get_service_last_accessed_details(JobId=unknown_job))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for unknown JobId, got {code}: {message!r}"
    expected = f"Job {unknown_job} does not exist."
    assert message == expected, f"NoSuchEntity message: expected {expected!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

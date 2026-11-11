"""get-service-last-accessed-details-with-entities-contract."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-service-last-accessed-details-with-entities-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetServiceLastAccessedDetailsWithEntities lists entities for a namespace the role's policy
    grants (s3), and for an ungranted namespace (iam) succeeds COMPLETED with no entities."""
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-gsladwe-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "get-service-last-accessed-details-with-entities-contract"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    s3_policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn))

    gen = iam.generate_service_last_accessed_details(Arn=role_arn)
    job_id = gen["JobId"]

    job = _poll_until(
        lambda: iam.get_service_last_accessed_details(JobId=job_id),
        lambda r: r["JobStatus"] in ("COMPLETED", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert job["JobStatus"] == "COMPLETED", f"job did not complete: {job}"

    # A non-empty list is required, or this leg cannot be told apart from the "iam" leg below.
    resp = iam.get_service_last_accessed_details_with_entities(JobId=job_id, ServiceNamespace="s3")
    assert resp["JobStatus"] == "COMPLETED"
    assert resp["EntityDetailsList"], (
        f"expected the granted namespace ('s3') to report at least one covered entity, "
        f"got {resp['EntityDetailsList']!r}"
    )

    # AWS does not reject a valid namespace the role's policies never reference; it reports none.
    resp_iam = iam.get_service_last_accessed_details_with_entities(JobId=job_id, ServiceNamespace="iam")
    assert resp_iam["JobStatus"] == "COMPLETED", f"expected COMPLETED for mismatched namespace, got {resp_iam}"
    assert resp_iam["EntityDetailsList"] == [], (
        f"expected no entities for a namespace never referenced by the role's policies, "
        f"got {resp_iam['EntityDetailsList']}"
    )


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

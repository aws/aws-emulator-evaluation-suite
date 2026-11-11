"""service-last-accessed-details-generation-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "service-last-accessed-details-generation-lifecycle"
GROUP = "server-side"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Service-last-accessed jobs complete for a role (s3 listed) and a managed policy (role listed
    as an s3 entity); ListPoliciesGrantingServiceAccess names the inline and managed policy."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sla-role-")
    inline_policy_name = ctx.unique_name("sim2real-sla-inline-")
    managed_policy_name = ctx.unique_name("sim2real-sla-managed-")

    trust_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_doc,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    s3_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}],
    })
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=s3_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    managed_policy_arn = iam.create_policy(
        PolicyName=managed_policy_name,
        PolicyDocument=s3_doc,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=managed_policy_arn))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    # Service-level job against the role.
    role_job_id = iam.generate_service_last_accessed_details(Arn=role_arn)["JobId"]
    role_report = _poll_until(
        lambda: iam.get_service_last_accessed_details(JobId=role_job_id),
        lambda r: r["JobStatus"] in ("COMPLETED", "FAILED"),
        timeout_s=60.0,
    )
    assert role_report["JobStatus"] == "COMPLETED", f"expected COMPLETED, got {role_report}"
    accessible_services = {s["ServiceNamespace"] for s in role_report["ServicesLastAccessed"]}
    assert "s3" in accessible_services, (
        f"expected s3 among the role's reported services, got {accessible_services}"
    )

    # Cross-reference: which policies grant this role s3 access.
    grants = iam.list_policies_granting_service_access(
        Arn=role_arn, ServiceNamespaces=["s3"]
    )["PoliciesGrantingServiceAccess"]
    assert len(grants) == 1, f"expected exactly one s3 namespace entry, got {grants}"
    granting_names = {(p["PolicyName"], p["PolicyType"]) for p in grants[0]["Policies"]}
    assert (inline_policy_name, "INLINE") in granting_names, (
        f"expected the inline policy {inline_policy_name!r} among s3 grants, got {granting_names}"
    )
    assert (managed_policy_name, "MANAGED") in granting_names, (
        f"expected the managed policy {managed_policy_name!r} among s3 grants, got {granting_names}"
    )

    # Entity-level job against the managed policy: which principals could use it for s3.
    policy_job_id = iam.generate_service_last_accessed_details(Arn=managed_policy_arn)["JobId"]
    policy_report = _poll_until(
        lambda: iam.get_service_last_accessed_details(JobId=policy_job_id),
        lambda r: r["JobStatus"] in ("COMPLETED", "FAILED"),
        timeout_s=60.0,
    )
    assert policy_report["JobStatus"] == "COMPLETED", f"expected COMPLETED, got {policy_report}"

    with_entities = iam.get_service_last_accessed_details_with_entities(
        JobId=policy_job_id, ServiceNamespace="s3"
    )
    entity_names = {
        (e["EntityInfo"]["Name"], e["EntityInfo"]["Type"])
        for e in with_entities["EntityDetailsList"]
    }
    assert (role_name, "ROLE") in entity_names, (
        f"expected role {role_name!r} among entities using the managed policy for s3, got {entity_names}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"poll did not reach a terminal state within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

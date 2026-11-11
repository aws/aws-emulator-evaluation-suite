"""op-run-job-flow-rejects-unknown-instance-profile."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone


from behavioral_harness import tags

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

_EMR_SERVICE_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
# Legacy policy, deliberately: AmazonEMRServicePolicy_v2 only grants EMR access to network
# resources tagged for-use-with-amazon-emr-managed-policies.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _ensure_emr_service_role(ctx):
    """Create a VALID EMR service role (deleted on teardown). Returns its name.

    This check asserts the rejection message names the bogus INSTANCE PROFILE, which means EMR has
    to get as far as validating it. A hardcoded EMR_DefaultRole would make that conditional on account
    state: in a fresh account the role does not exist, EMR rejects on the unassumable SERVICE role
    first, and the check fails for a reason that has nothing to do with the invariant under test.
    So the valid half of the request is built here and only the profile is left bogus.
    """
    iam = ctx.client("iam")
    role = _unique_name("emr-svc-")
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=_EMR_SERVICE_TRUST,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    # Cleanups run LIFO, so the delete registered here runs AFTER the detach registered below.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role, PolicyArn=_SERVICE_POLICY))
    return role


def _recent_cutoff(minutes=15):
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)

CHECK = "op-run-job-flow-rejects-unknown-instance-profile"
GROUP = 'overly-permissive'
SERVICES = ['emr']

def _rejects_bogus_profile(emr, name, service_role, bogus_profile, deadline_s=90):
    """Resubmit RunJobFlow until its rejection names *bogus_profile*; return the (code, message).

    Right after the service role is created, IAM's eventual consistency means EMR can reject the
    call because it cannot yet see the (valid) SERVICE role, before validation ever reaches the
    instance profile — the same request, rejected for the wrong reason. Retry the identical call on
    a bounded deadline until the rejection is actually about the profile under test, or the deadline
    elapses and the last rejection is what gets asserted below.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            emr.run_job_flow(
                Name=name,
                ReleaseLabel=RELEASE_LABEL,
                Instances={
                    "InstanceCount": 1,
                    "MasterInstanceType": INSTANCE_TYPE,
                    "KeepJobFlowAliveWhenNoSteps": True,
                    "TerminationProtected": False,
                },
                ServiceRole=service_role,
                JobFlowRole=bogus_profile,
                VisibleToAllUsers=True,
            )
        except Exception as exc:
            err = (getattr(exc, "response", {}) or {}).get("Error", {})
            code, message = err.get("Code", type(exc).__name__), err.get("Message", "")
            if bogus_profile in message or time.monotonic() >= deadline:
                return code, message
            time.sleep(5)
            continue
        raise AssertionError("expected the operation to be rejected, but it succeeded")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: RunJobFlow resolves JobFlowRole to a real EC2 instance
    profile before launching. An unknown profile is rejected with
    ValidationException naming the profile, and no cluster is created."""
    emr = ctx.client("emr")
    name = _unique_name("emr-badprofile-")
    bogus_profile = "sim2real-behav-emr-no-such-profile"
    since = _recent_cutoff()
    service_role = _ensure_emr_service_role(ctx)

    code, message = _rejects_bogus_profile(emr, name, service_role, bogus_profile)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = f"Invalid InstanceProfile: {bogus_profile}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A rejected RunJobFlow must be atomic: no half-created cluster.
    created = [
        c["Name"]
        for page in emr.get_paginator("list_clusters").paginate(CreatedAfter=since)
        for c in page["Clusters"]
    ]
    assert name not in created, "a rejected RunJobFlow must not leave a cluster behind"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

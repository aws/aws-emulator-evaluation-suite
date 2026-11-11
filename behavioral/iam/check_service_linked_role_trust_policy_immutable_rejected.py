"""service-linked-role-trust-policy-immutable-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "service-linked-role-trust-policy-immutable-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAssumeRolePolicy on a service-linked role is rejected UnmodifiableEntity and leaves
    its trust policy unchanged, while the identical call succeeds on an ordinary role, so the
    rejection is specific to the service-linked role."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-behav-")[-20:]

    created = iam.create_service_linked_role(
        AWSServiceName="autoscaling.amazonaws.com", CustomSuffix=suffix
    )["Role"]
    role_name = created["RoleName"]
    # Read the trust policy back via GetRole (rather than trusting the CreateServiceLinkedRole
    # response body verbatim) so the "before" and "after" snapshots being compared come from the
    # same API/serialization path; on real AWS the freshly-created response's inline document can
    # differ cosmetically from what GetRole reports once the role is fully persisted.
    original_trust_policy = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            task_id = iam.delete_service_linked_role(RoleName=role_name)["DeletionTaskId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                return
            raise
        status = _poll_deletion_status(iam, task_id, role_name, timeout_s=60)
        if status != "SUCCEEDED":
            raise RuntimeError(f"service-linked role {role_name!r} deletion ended {status}")

    ctx.on_cleanup(_cleanup)

    attacker_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
        ],
    }

    code, message = _error_code(
        lambda: iam.update_assume_role_policy(
            RoleName=role_name, PolicyDocument=json.dumps(attacker_trust_policy)
        )
    )
    assert code == "UnmodifiableEntity", f"expected UnmodifiableEntity, got {code}"
    expected = (
        f"Cannot perform the operation on the protected role '{role_name}' - "
        "this role is only modifiable by AWS"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the trust policy must be unchanged after the rejected mutation attempt
    got = iam.get_role(RoleName=role_name)["Role"]
    assert got["AssumeRolePolicyDocument"] == original_trust_policy, (
        f"trust policy changed despite rejected UpdateAssumeRolePolicy: "
        f"expected {original_trust_policy}, got {got['AssumeRolePolicyDocument']}"
    )

    # Positive control: the identical PolicyDocument succeeds against an ordinary role, so the
    # UnmodifiableEntity above is specific to the service-linked role and not a broad failure of
    # UpdateAssumeRolePolicy in this account/region.
    ordinary_role_name = ctx.unique_name("sim2real-behav-ordinary-")
    iam.create_role(
        RoleName=ordinary_role_name, AssumeRolePolicyDocument=json.dumps(original_trust_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ordinary_role_name))
    iam.update_assume_role_policy(
        RoleName=ordinary_role_name, PolicyDocument=json.dumps(attacker_trust_policy)
    )
    ordinary_after = iam.get_role(RoleName=ordinary_role_name)["Role"]["AssumeRolePolicyDocument"]
    assert ordinary_after == attacker_trust_policy, (
        f"positive control failed: UpdateAssumeRolePolicy on an ordinary role should have applied "
        f"{attacker_trust_policy}, got {ordinary_after}"
    )


# ===== helpers =====


def _error_code(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so an accepted
    call never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_deletion_status(iam, deletion_task_id, role_name, timeout_s=60.0, interval_s=2.0):
    """Poll the deletion task to a terminal status; a task IAM does not track (NoSuchEntity)
    counts as SUCCEEDED only once GetRole also refuses with NoSuchEntity."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            resp = iam.get_service_linked_role_deletion_status(DeletionTaskId=deletion_task_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            try:
                iam.get_role(RoleName=role_name)
            except ClientError as role_exc:
                if role_exc.response["Error"]["Code"] == "NoSuchEntity":
                    return "SUCCEEDED"
                raise
            time.sleep(interval_s)
            continue
        status = resp["Status"]
        if status in ("SUCCEEDED", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"service-linked role deletion never reached a terminal state (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

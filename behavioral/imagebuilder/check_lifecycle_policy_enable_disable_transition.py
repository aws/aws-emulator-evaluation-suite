"""lifecycle-policy-enable-disable-transition."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lifecycle-policy-enable-disable-transition"
GROUP = "state-machine"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateLifecyclePolicy toggles status between DISABLED and ENABLED and GetLifecyclePolicy reflects each transition."""
    ib = ctx.client("imagebuilder")
    role_arn = _create_execution_role(ctx)

    policy_details = [
        {
            "action": {"type": "DELETE"},
            "filter": {"type": "AGE", "value": 365, "unit": "DAYS", "retainAtLeast": 1},
        }
    ]
    resource_selection = {"tagMap": {"sim2real-lifecycle-check": "true"}}

    arn = _create_lifecycle_policy_with_retry(
        ib,
        name=ctx.unique_name("sim2real-lcp-"),
        executionRole=role_arn,
        resourceType="AMI_IMAGE",
        policyDetails=policy_details,
        resourceSelection=resource_selection,
        status="DISABLED",
        tags={"sim2real-lifecycle-check": "true"},
    )
    ctx.on_cleanup(lambda: ib.delete_lifecycle_policy(lifecyclePolicyArn=arn))

    status_after_create = ib.get_lifecycle_policy(lifecyclePolicyArn=arn)["lifecyclePolicy"]["status"]
    assert status_after_create == "DISABLED", f"expected status=DISABLED after create, got {status_after_create!r}"

    ib.update_lifecycle_policy(
        lifecyclePolicyArn=arn,
        executionRole=role_arn,
        resourceType="AMI_IMAGE",
        policyDetails=policy_details,
        resourceSelection=resource_selection,
        status="ENABLED",
        clientToken=str(uuid.uuid4()),
    )
    status_after_update = ib.get_lifecycle_policy(lifecyclePolicyArn=arn)["lifecyclePolicy"]["status"]
    assert status_after_update == "ENABLED", f"expected status=ENABLED after update, got {status_after_update!r}"


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ib-lcp-role-")
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"imagebuilder.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-lifecycle-check", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_lifecycle_policy_with_retry(ib, timeout_s=90.0, **kwargs):
    # a freshly created IAM role can take a short while to propagate before
    # Image Builder can validate/assume it as an executionRole; poll the
    # actual create call rather than sleeping a fixed duration.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ib.create_lifecycle_policy(clientToken=str(uuid.uuid4()), **kwargs)["lifecyclePolicyArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidRequestException", "InvalidParameterValueException"):
                raise
            last_exc = exc
            time.sleep(3)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

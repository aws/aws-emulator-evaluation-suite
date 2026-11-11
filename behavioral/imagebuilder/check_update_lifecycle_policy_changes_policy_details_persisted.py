"""update-lifecycle-policy-changes-policy-details-persisted."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-lifecycle-policy-changes-policy-details-persisted"
GROUP = "state-machine"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateLifecyclePolicy can replace the action type in policyDetails; GetLifecyclePolicy reflects it."""
    ib = ctx.client("imagebuilder")
    role_arn = _create_lifecycle_execution_role(ctx)
    name = ctx.unique_name("sim2real-ib-lcp-")
    tag_key = ctx.unique_name("sim2real-ib-lcp-tag-")
    resource_selection = {"tagMap": {tag_key: "true"}}

    policy_arn = _create_lifecycle_policy_with_retry(
        ib,
        name=name,
        executionRole=role_arn,
        resourceType="AMI_IMAGE",
        policyDetails=[{"action": {"type": "DEPRECATE"}, "filter": {"type": "AGE", "value": 30, "unit": "DAYS"}}],
        resourceSelection=resource_selection,
        status="DISABLED",
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: ib.delete_lifecycle_policy(lifecyclePolicyArn=policy_arn))

    got = ib.get_lifecycle_policy(lifecyclePolicyArn=policy_arn)["lifecyclePolicy"]
    action_before = got["policyDetails"][0]["action"]["type"]
    assert action_before == "DEPRECATE", f"expected freshly created policy action DEPRECATE, got {action_before}"

    ib.update_lifecycle_policy(
        lifecyclePolicyArn=policy_arn,
        executionRole=role_arn,
        resourceType="AMI_IMAGE",
        policyDetails=[{"action": {"type": "DELETE"}, "filter": {"type": "COUNT", "value": 3}}],
        resourceSelection=resource_selection,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
    )

    got_after = ib.get_lifecycle_policy(lifecyclePolicyArn=policy_arn)["lifecyclePolicy"]
    action_after = got_after["policyDetails"][0]["action"]["type"]
    filter_value_after = got_after["policyDetails"][0]["filter"]["value"]
    assert action_after == "DELETE", f"expected updated policy action DELETE, got {action_after}"
    assert filter_value_after == 3, f"expected updated filter value 3, got {filter_value_after}"


def _create_lifecycle_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ib-lcp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "imagebuilder.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/EC2ImageBuilderLifecycleExecutionPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return resp["Role"]["Arn"]


def _create_lifecycle_policy_with_retry(ib, timeout_s=90.0, **kwargs):
    # a freshly created IAM role (and its freshly attached managed policy) can take a short
    # while to propagate before Image Builder can validate/assume it as an executionRole; poll
    # the actual create call rather than sleeping a fixed duration.
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

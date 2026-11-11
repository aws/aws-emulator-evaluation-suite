"""test-state-pass-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-pass-state"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
                "Resource": "*",
            }
        ],
    }
)


def _create_sfn_role(ctx):
    """Create an execution role Step Functions can assume; it is deleted at teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for fn in (
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)
    return arn


def _await_role(fn, *, timeout_s=90.0):
    """Call fn(), retrying AccessDeniedException while a new role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState simulates a single Pass state and returns its Result as output.

    No real execution or state machine is created.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    definition = json.dumps({"Type": "Pass", "Result": {"simulated": True}})
    resp = _await_role(lambda: sfn.test_state(definition=definition, roleArn=role_arn, input="{}"))
    assert resp["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {resp}"
    output = json.loads(resp["output"])
    assert output == {"simulated": True}, f"expected Result echoed as output, got {output}"

    passthrough_definition = json.dumps({"Type": "Pass"})
    passthrough_input = {"untouched": "value", "count": 7}
    passthrough_resp = sfn.test_state(
        definition=passthrough_definition,
        roleArn=role_arn,
        input=json.dumps(passthrough_input),
    )
    assert passthrough_resp["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED, got {passthrough_resp}"
    )
    passthrough_output = json.loads(passthrough_resp["output"])
    assert passthrough_output == passthrough_input, (
        f"Pass state with no Result must pass input through unchanged, "
        f"expected {passthrough_input}, got {passthrough_output}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

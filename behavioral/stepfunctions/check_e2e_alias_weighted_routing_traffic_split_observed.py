"""e2e-alias-weighted-routing-traffic-split-observed."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-alias-weighted-routing-traffic-split-observed"
GROUP = "e2e"
SERVICES = ["stepfunctions"]

_N_EXECUTIONS = 60
_WEIGHT_V1 = 20
_WEIGHT_V2 = 80


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Executions started through a weighted alias distribute across the two backing versions
    in proportion to the configured routing weights."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _pass_definition("v1"))
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    sfn.update_state_machine(stateMachineArn=sm_arn, definition=_pass_definition("v2"))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    alias_name = ctx.unique_name("sim2real-sfn-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name,
        routingConfiguration=[
            {"stateMachineVersionArn": v1_arn, "weight": _WEIGHT_V1},
            {"stateMachineVersionArn": v2_arn, "weight": _WEIGHT_V2},
        ],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))

    exec_arns = [
        sfn.start_execution(stateMachineArn=alias_arn, input="{}")["executionArn"]
        for _ in range(_N_EXECUTIONS)
    ]

    def _wait_one(arn):
        return _poll_until(
            lambda: sfn.describe_execution(executionArn=arn),
            lambda d: d["status"] != "RUNNING",
            timeout_s=30.0,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        descs = list(pool.map(_wait_one, exec_arns))

    version_arns = [d["stateMachineVersionArn"] for d in descs]
    assert all(v in (v1_arn, v2_arn) for v in version_arns), (
        f"execution routed to a version outside the alias's own routing config: {version_arns}"
    )
    v1_count = sum(1 for v in version_arns if v == v1_arn)
    v2_count = sum(1 for v in version_arns if v == v2_arn)
    assert v1_count + v2_count == _N_EXECUTIONS, (
        f"expected all {_N_EXECUTIONS} executions accounted for by version; "
        f"got v1={v1_count} v2={v2_count}"
    )

    # Weights are 20/80 -- with N=60 the odds of the minority version getting zero traffic
    # (0.8**60, about 1.5e-6), or outnumbering the majority one, are negligible under real
    # weighted routing.
    # Both legs matter: without the first, a target that ignores the minority weight entirely and
    # always routes to the latest/highest-weighted version would still pass.
    assert v1_count > 0, (
        f"expected v1 (weight={_WEIGHT_V1}) to receive at least one of {_N_EXECUTIONS} "
        f"executions; got v1=0 v2={v2_count} -- alias may be ignoring its minority weight and "
        f"always routing to the latest/highest-weighted version"
    )
    assert v2_count > v1_count, (
        f"expected v2 (weight={_WEIGHT_V2}) to dominate v1 (weight={_WEIGHT_V1}); "
        f"got v1={v1_count} v2={v2_count}"
    )


def _pass_definition(version: str) -> str:
    return json.dumps(
        {
            "StartAt": "S",
            "States": {"S": {"Type": "Pass", "Result": {"version": version}, "End": True}},
        }
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-sm-")
    last_err = None
    for _ in range(15):
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
            arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

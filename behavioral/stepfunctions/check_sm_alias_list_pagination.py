"""sm-alias-list-pagination."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sm-alias-list-pagination"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStateMachineAliases returns all aliases created for a state
    machine, and paginates correctly with a small page size."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _SIMPLE_DEFINITION)
    sfn = ctx.client("stepfunctions")
    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    created_names = set()
    for _ in range(4):
        alias_name = ctx.unique_name("sim2real-alias-")
        alias_arn = sfn.create_state_machine_alias(
            name=alias_name,
            routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
        )["stateMachineAliasArn"]
        ctx.on_cleanup(lambda a=alias_arn: _swallow(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=a)))
        created_names.add(alias_name)

    def _scan_all_pages():
        seen = set()
        next_token = None
        page_count = 0
        while True:
            kwargs = {"stateMachineArn": sm_arn, "maxResults": 1}
            if next_token:
                kwargs["nextToken"] = next_token
            page = sfn.list_state_machine_aliases(**kwargs)
            page_count += 1
            for a in page["stateMachineAliases"]:
                seen.add(a["stateMachineAliasArn"].rsplit(":", 1)[-1])
            next_token = page.get("nextToken")
            if not next_token or page_count > 20:
                break
        return page_count, seen

    # ListStateMachineAliases can lag briefly behind a just-completed create, so poll the full
    # paginated scan until every created alias is visible before judging page count.
    deadline = time.monotonic() + 30.0
    pages, seen_names = _scan_all_pages()
    while not created_names.issubset(seen_names):
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
        pages, seen_names = _scan_all_pages()

    assert created_names.issubset(seen_names), f"missing aliases: {created_names - seen_names}"
    assert pages >= len(created_names), f"expected multi-page pagination, got {pages} pages"


_SIMPLE_DEFINITION = {
    "Comment": "simple",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "ok", "End": True}},
}

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)

    def _cleanup():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn, definition, *, name=None, sm_type="STANDARD"):
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-sfn-")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real:managed", "value": "true"}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""list-executions-maxresults-change-keeps-token-valid."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-executions-maxresults-change-keeps-token-valid"
GROUP = "execution_lifecycle"
SERVICES = ["stepfunctions"]

_N_EXECUTIONS = 5

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


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)["Role"][
        "Arn"
    ]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}})
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_terminal(sfn, exec_arn, *, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListExecutions' nextToken stays valid across a change in maxResults between pages:
    walking the same stateMachineArn with a different page size on every call still
    enumerates every execution exactly once."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    exec_arns = []
    for i in range(_N_EXECUTIONS):
        exec_arn = sfn.start_execution(stateMachineArn=sm_arn, name=ctx.unique_name(f"exec{i}-"))[
            "executionArn"
        ]
        ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
        exec_arns.append(exec_arn)
    for exec_arn in exec_arns:
        _wait_terminal(sfn, exec_arn)

    # Positive control: an unpaginated call returns every execution we started.
    baseline = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    baseline_arns = {e["executionArn"] for e in baseline}
    assert set(exec_arns) <= baseline_arns, (
        f"positive control: expected all of {exec_arns} in an unpaginated ListExecutions, "
        f"got {sorted(baseline_arns)}"
    )

    # Walk the same listing with a page size that changes on every call.
    page_sizes = [1, 3, 2, 4, 1]
    walked = []
    token = None
    page_index = 0
    while True:
        kwargs = {"stateMachineArn": sm_arn, "maxResults": page_sizes[page_index % len(page_sizes)]}
        if token:
            kwargs["nextToken"] = token
        page = sfn.list_executions(**kwargs)
        walked.extend(page["executions"])
        token = page.get("nextToken")
        page_index += 1
        if not token:
            break
        if page_index > 50:
            raise AssertionError("ListExecutions pagination did not terminate within 50 pages")

    walked_arns = [e["executionArn"] for e in walked]
    assert len(walked_arns) == len(set(walked_arns)), (
        f"duplicate executions across pages with changing maxResults: {walked_arns}"
    )
    assert set(exec_arns) <= set(walked_arns), (
        f"expected all of {exec_arns} walked with a changing page size, got {sorted(set(walked_arns))}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

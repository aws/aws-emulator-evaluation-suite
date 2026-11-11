"""choice-string-matches-path-comparators-and-precedence."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-string-matches-path-comparators-and-precedence"
GROUP = 'choice_state'
SERVICES = ['stepfunctions']


# ===== helpers =====
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


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_sfn_role(ctx):
    """An execution role this check creates for its own state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    return arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    # A fresh role takes a few seconds before Step Functions may assume it.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)
# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StringMatches wildcards, StringEqualsPath, TimestampGreaterThan (compared as instants) and Or
    route a Choice state correctly, and when every rule matches the FIRST matching rule wins.
    """
    definition = {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {
                        "Variable": "$.key",
                        "StringMatches": "reports/2024-*.csv",
                        "Next": "MatchedWildcard",
                    },
                    {"Variable": "$.left", "StringEqualsPath": "$.right", "Next": "PathEqual"},
                    {
                        "Variable": "$.when",
                        "TimestampGreaterThan": "2020-01-01T00:00:00Z",
                        "Next": "AfterCutoff",
                    },
                    {
                        "Or": [
                            {"Variable": "$.n", "NumericLessThan": 0},
                            {"Variable": "$.n", "NumericGreaterThanEquals": 100},
                        ],
                        "Next": "OutOfRange",
                    },
                ],
                "Default": "NoMatch",
            },
            "MatchedWildcard": {"Type": "Pass", "Result": "wildcard", "End": True},
            "PathEqual": {"Type": "Pass", "Result": "path-equal", "End": True},
            "AfterCutoff": {"Type": "Pass", "Result": "after-cutoff", "End": True},
            "OutOfRange": {"Type": "Pass", "Result": "out-of-range", "End": True},
            "NoMatch": {"Type": "Pass", "Result": "no-match", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition)

    def case(*, key, left, right, when, n):
        return {"key": key, "left": left, "right": right, "when": when, "n": n}

    inert = {
        "key": "logs/other.txt",
        "left": "a",
        "right": "b",
        "when": "2019-01-01T00:00:00Z",
        "n": 50,
    }
    cases = [
        (
            case(**{**inert, "key": "reports/2024-08-31.csv"}),
            "wildcard",
            "StringMatches must expand '*' inside a literal prefix/suffix",
        ),
        (
            case(**{**inert, "key": "reports/2023-08-31.csv"}),
            "no-match",
            "StringMatches must NOT match when the literal prefix differs (2023 vs 2024-*)",
        ),
        (
            case(**{**inert, "left": "same", "right": "same"}),
            "path-equal",
            "StringEqualsPath must compare $.left against the VALUE at $.right",
        ),
        (
            case(**{**inert, "when": "2021-06-01T00:00:00Z"}),
            "after-cutoff",
            "TimestampGreaterThan must compare RFC3339 instants",
        ),
        (
            case(**{**inert, "n": 250}),
            "out-of-range",
            "Or must match when its second sub-rule (NumericGreaterThanEquals) is true",
        ),
        (
            case(**{**inert, "n": -5}),
            "out-of-range",
            "Or must match when its first sub-rule (NumericLessThan) is true",
        ),
        (inert, "no-match", "no rule matches, so Default must be taken"),
        (
            case(key="reports/2024-01-01.csv", left="same", right="same", when="2021-06-01T00:00:00Z", n=-5),
            "wildcard",
            "all four rules match; Step Functions takes the FIRST matching Choices entry",
        ),
    ]

    for input_data, expected, why in cases:
        desc = _wait_execution_complete(
            ctx, _start_execution(ctx, sm_arn, input_data=input_data), timeout_s=60
        )
        assert desc["status"] == "SUCCEEDED", (
            f"input {input_data!r} did not reach SUCCEEDED: {desc.get('status')} "
            f"error={desc.get('error')} cause={desc.get('cause')}"
        )
        got = _get_output(desc)
        assert got == expected, (
            f"input {input_data!r} routed to {got!r}, expected {expected!r} -- {why}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""list-scheduled-queries-deterministic-ordering."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-scheduled-queries-deterministic-ordering"
GROUP = "ordering"
SERVICES = ["logs"]

_SCHEDULE = "cron(8 * * * ? *)"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListScheduledQueries lists the created summaries in a stable order across repeated
    calls when nothing mutates in between."""
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]
    # describe_log_groups returns the ARN with a trailing ":*" wildcard
    # suffix, which CreateScheduledQuery's logGroupIdentifiers field rejects
    # with ValidationException (it doesn't allow "*" in the identifier
    # pattern). Strip it to get the plain group ARN the API actually accepts.
    if group_arn.endswith(":*"):
        group_arn = group_arn[: -len(":*")]

    role_name = ctx.unique_name("sim2real-behav-sq-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    exec_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:StartQuery",
                    "logs:StopQuery",
                    "logs:GetQueryResults",
                    "logs:DescribeLogGroups",
                ],
                "Resource": "*",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-sq-exec",
        PolicyDocument=json.dumps(exec_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-behav-sq-exec")
    )

    query_names = [ctx.unique_name(f"sim2real-behav-sq-{i}-") for i in range(3)]
    created = {}
    for name in query_names:
        arn = _create_scheduled_query_with_retry(
            logs, name=name, role_arn=role_arn, log_group_arn=group_arn
        )
        created[name] = arn
        ctx.on_cleanup(lambda a=arn: logs.delete_scheduled_query(identifier=a))

    first_order = _list_our_queries(logs, query_names)
    second_order = _list_our_queries(logs, query_names)

    assert len(first_order) == len(query_names) == len(second_order), (
        f"expected {len(query_names)} of our scheduled queries visible in both listings, "
        f"got {len(first_order)} then {len(second_order)}: {first_order!r} / {second_order!r}"
    )
    assert first_order == second_order, (
        f"ListScheduledQueries order changed across two back-to-back calls with no "
        f"mutation in between: {first_order} != {second_order}"
    )
    expected = {(n, created[n], "ENABLED", _SCHEDULE) for n in query_names}
    assert set(first_order) == expected, (
        f"ListScheduledQueries summaries (name, arn, state, scheduleExpression) "
        f"{sorted(first_order)!r}, expected {sorted(expected)!r}"
    )


def _create_scheduled_query_with_retry(logs, *, name, role_arn, log_group_arn, timeout_s=45.0):
    """IAM role trust/attached policy can take a few seconds to propagate; retry
    through the window where CreateScheduledQuery can't yet see the role."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = logs.create_scheduled_query(
                name=name,
                queryLanguage="CWLI",
                queryString="fields @timestamp, @message | limit 10",
                scheduleExpression=_SCHEDULE,
                # CreateScheduledQuery requires startTimeOffset -- the number
                # of seconds before each scheduled invocation time to use as
                # the query's start time window.
                startTimeOffset=3600,
                executionRoleArn=role_arn,
                logGroupIdentifiers=[log_group_arn],
                state="ENABLED",
                tags={"Sim2RealOwner": "behavioral-suite"},
            )
            return resp["scheduledQueryArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException", "InvalidParameterException"):
                last_err = e
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"CreateScheduledQuery never accepted the execution role: {last_err}")


def _list_our_queries(logs, query_names):
    order = []
    next_token = None
    while True:
        kwargs = {} if next_token is None else {"nextToken": next_token}
        resp = logs.list_scheduled_queries(**kwargs)
        for q in resp.get("scheduledQueries", []):
            if q.get("name") in query_names:
                order.append(
                    (q["name"], q.get("scheduledQueryArn"), q.get("state"), q.get("scheduleExpression"))
                )
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return order


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

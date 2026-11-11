"""filter-criteria-nested-json-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-criteria-nested-json-preserved"
GROUP = "representation"
SERVICES = ["pipes"]

_TRANSITIONAL = {"CREATING", "UPDATING", "DELETING", "STARTING", "STOPPING"}
_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:check": CHECK}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]

# A deeply nested EventBridge-style event pattern (nested field matching, array-valued leaves).
_PATTERN = {
    "body": {
        "metadata": {
            "region": {
                "zone": {
                    "level": ["deep-value-1", "deep-value-2", "deep-value-3"],
                }
            },
            "tags": {"env": ["prod", "staging"]},
        }
    }
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deeply nested FilterCriteria JSON pattern is returned with identical structure by DescribePipe."""
    source_url, source_arn = _create_queue(ctx, "sim2real-pipes-src-")
    _, target_arn = _create_queue(ctx, "sim2real-pipes-tgt-")
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)

    pattern_str = json.dumps(_PATTERN)
    pipes = ctx.client("pipes")
    name = ctx.unique_name("sim2real-pipes-filter-")
    pipes.create_pipe(
        Name=name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        SourceParameters={"FilterCriteria": {"Filters": [{"Pattern": pattern_str}]}},
        DesiredState="STOPPED",
        Tags=_resource_tags(),
    )
    ctx.on_cleanup(lambda: _best_effort_delete_pipe(pipes, name))
    _wait_pipe_stable(ctx, name)

    described = pipes.describe_pipe(Name=name)
    filters = described["SourceParameters"]["FilterCriteria"]["Filters"]
    assert len(filters) == 1, f"expected exactly one filter, got {len(filters)}"
    returned_pattern = json.loads(filters[0]["Pattern"])
    assert returned_pattern == _PATTERN, (
        f"nested filter pattern not preserved: {returned_pattern!r} != {_PATTERN!r}"
    )
    # Sanity check the depth/array structure specifically survived (not flattened).
    level = returned_pattern["body"]["metadata"]["region"]["zone"]["level"]
    assert level == ["deep-value-1", "deep-value-2", "deep-value-3"], (
        f"nested array leaf flattened or reordered: expected "
        f"['deep-value-1', 'deep-value-2', 'deep-value-3'], got {level!r}"
    )

    pipes.delete_pipe(Name=name)
    _wait_pipe_deleted(ctx, name)


def _create_queue(ctx, prefix):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, source_arn, target_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_resource_tags_kv(),
    )
    role_arn = role["Role"]["Arn"]
    policy_name = "pipe-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_pipe_stable(ctx, name, timeout_s=90.0, interval_s=3.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pipes.describe_pipe(Name=name)
        if last["CurrentState"] not in _TRANSITIONAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"pipe {name} did not stabilize within {timeout_s}s "
        f"(last state {last['CurrentState'] if last else None})"
    )


def _best_effort_delete_pipe(pipes, name):
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _wait_pipe_deleted(ctx, name, timeout_s=60.0, interval_s=3.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            assert code == "NotFoundException", (
                f"expected DescribePipe to fail with NotFoundException after DeletePipe, got {code!r}"
            )
            expected_message = f"Pipe {name} does not exist."
            assert message == expected_message, (
                f"DescribePipe after DeletePipe: expected message {expected_message!r}, got {message!r}"
            )
            return
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} still describable {timeout_s}s after DeletePipe")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

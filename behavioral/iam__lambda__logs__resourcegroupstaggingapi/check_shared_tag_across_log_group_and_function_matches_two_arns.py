"""shared-tag-across-log-group-and-function-matches-two-arns."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shared-tag-across-log-group-and-function-matches-two-arns"
GROUP = "tagging-discovery"
SERVICES = ["iam", "lambda", "logs", "resourcegroupstaggingapi"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_HANDLER_SRC = "def handler(event, context):\n    return event\n"

#: The exact (code, message) a fresh role's not-yet-propagated trust policy raises.
_ROLE_NOT_PROPAGATED = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
)


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """One tag shared by a log group and a Lambda function is an exact two-ARN GetResources
    match, each entry carrying only that tag, and the log group's indexed ARN drops the ':*'
    DescribeLogGroups appends to its own.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    rgt = ctx.client("resourcegroupstaggingapi")

    role_name = ctx.unique_name("sim2real-behav-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    fn_name = ctx.unique_name("sim2real-behav-fn-")
    function_arn = _create_function(lam, fn_name, role_arn)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    log_group_name = "/" + ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(_teardown(
        lambda: logs.delete_log_group(logGroupName=log_group_name),
        "ResourceNotFoundException",
    ))

    described = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    assert len(described) == 1 and described[0]["logGroupName"] == log_group_name, (
        f"DescribeLogGroups(logGroupNamePrefix={log_group_name!r}) returned {described!r}, "
        f"expected exactly one group named {log_group_name!r}"
    )
    native_arn = described[0]["arn"]
    assert native_arn.endswith(":*"), (
        f"the log group's own arn {native_arn!r} does not end with ':*'"
    )
    index_arn = native_arn[: -len(":*")]

    tag_key = ctx.unique_name("sim2real-behav-tagkey-")
    tag_value = ctx.unique_name("sim2real-behav-tagval-")

    lam.tag_resource(Resource=function_arn, Tags={tag_key: tag_value})
    logs.tag_log_group(logGroupName=log_group_name, tags={tag_key: tag_value})

    mappings = _poll_until(
        lambda: rgt.get_resources(TagFilters=[{"Key": tag_key, "Values": [tag_value]}])[
            "ResourceTagMappingList"
        ],
        lambda m: len(m) == 2,
        timeout_s=180.0,
    )
    found = {m["ResourceARN"]: m["Tags"] for m in mappings}
    assert set(found) == {function_arn, index_arn}, (
        f"GetResources(TagFilters=[{{'Key': {tag_key!r}, 'Values': [{tag_value!r}]}}]) matched "
        f"{sorted(found)!r}, expected exactly [{function_arn!r}, {index_arn!r}]"
    )
    for arn in (function_arn, index_arn):
        assert found[arn] == [{"Key": tag_key, "Value": tag_value}], (
            f"{arn!r} carries Tags={found[arn]!r}, expected exactly "
            f"[{{'Key': {tag_key!r}, 'Value': {tag_value!r}}}]"
        )


def _create_function(lam, name: str, role_arn: str, *, timeout_s: float = 90.0) -> str:
    """Create the function, retrying only the fresh-role propagation refusal, exact pair."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": _zip_bytes()},
                MemorySize=128, Timeout=10,
            )["FunctionArn"]
        except ClientError as exc:
            err = exc.response["Error"]
            pair = (err["Code"], err["Message"])
            if pair != _ROLE_NOT_PROPAGATED or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", _HANDLER_SRC)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except on ``not_found``."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        result = probe()
        if predicate(result):
            return result
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s; last observed value was {result!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

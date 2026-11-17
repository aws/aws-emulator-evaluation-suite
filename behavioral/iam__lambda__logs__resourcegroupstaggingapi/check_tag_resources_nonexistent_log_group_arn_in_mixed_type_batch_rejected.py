"""tag-resources-nonexistent-log-group-arn-in-mixed-type-batch-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-log-group-arn-in-mixed-type-batch-rejected"
GROUP = "tagging-discovery"
SERVICES = ["iam", "lambda", "logs", "resourcegroupstaggingapi"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_HANDLER_SRC = "def handler(event, context):\n    return event\n"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResources batching a live Lambda function with a well-formed but never-created
    log-group ARN of a different resource type tags the function, reports only the log-group ARN
    in FailedResourcesMap with CloudWatch Logs' own not-found error.
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

    fn = ctx.unique_name("sim2real-behav-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    function_arn = _create_function(lam, fn, role_arn)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))

    ghost_name = "/" + ctx.unique_name("sim2real-behav-ghost-lg-")
    ghost_arn = f"arn:aws:logs:{ctx.region}:{ctx.account}:log-group:{ghost_name}"
    preexisting = logs.describe_log_groups(logGroupNamePrefix=ghost_name)["logGroups"]
    assert preexisting == [], (
        f"the ghost log group name {ghost_name!r} must never have been created; "
        f"DescribeLogGroups found {preexisting!r}"
    )

    tag_key = ctx.unique_name("sim2real-behav-tagkey-")
    tag_value = ctx.unique_name("sim2real-behav-tagval-")
    resp = rgt.tag_resources(
        ResourceARNList=[function_arn, ghost_arn], Tags={tag_key: tag_value},
    )

    failed = resp["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the never-created "
        f"log group {ghost_arn!r} -- the live function {function_arn!r} must not fail and the "
        f"absent log group must not pass"
    )
    detail = failed[ghost_arn]
    got = (detail["ErrorCode"], detail["StatusCode"], detail["ErrorMessage"])
    expected = (
        "ResourceNotFoundException", 400,
        "The specified log group does not exist.",
    )
    assert got == expected, (
        f"the never-created log group's (ErrorCode, StatusCode, ErrorMessage) was {got!r}, "
        f"expected {expected!r}"
    )

    native_tags = lam.get_function(FunctionName=fn)["Tags"]
    assert native_tags == {tag_key: tag_value}, (
        f"GetFunction reports Tags={native_tags!r} for the live function in the same batch; "
        f"expected exactly {{{tag_key!r}: {tag_value!r}}} despite the other ARN's failure"
    )


#: The exact (code, message) a fresh role's not-yet-propagated trust policy raises.
_ROLE_NOT_PROPAGATED = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
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


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    ``delete_function`` does not remove ``/aws/lambda/<fn>``, and a buffered flush can recreate
    it after a delete, so one ``delete_log_group`` is one round, not a teardown.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"{name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

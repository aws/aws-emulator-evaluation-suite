"""cfn-ecr-repository-name-string-constraints-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecr-repository-name-string-constraints-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}
_HANDLER_SUFFIX = "<token>, HandlerErrorCode: InvalidRequest)"
_REQUEST_TOKEN = re.compile(r"\(RequestToken: [^,)]+")
_MINLEN_REASON = (
    'Resource handler returned message: "Model validation failed '
    "(#/RepositoryName: 2 schema violations found)\n"
    "#/RepositoryName: expected minLength: 2, actual: 1 (#/RepositoryName)\n"
    "#/RepositoryName: failed validation constraint for keyword [pattern] "
    '(#/RepositoryName)" (RequestToken: ' + _HANDLER_SUFFIX
)
_MAXLEN_REASON = (
    'Resource handler returned message: "Model validation failed '
    "(#/RepositoryName: 2 schema violations found)\n"
    "#/RepositoryName: expected maxLength: 256, actual: 257 (#/RepositoryName)\n"
    "#/RepositoryName: failed validation constraint for keyword [pattern] "
    '(#/RepositoryName)" (RequestToken: ' + _HANDLER_SUFFIX
)
_PATTERN_REASON = (
    'Resource handler returned message: "Model validation failed '
    '(#/RepositoryName: failed validation constraint for keyword [pattern])" '
    "(RequestToken: " + _HANDLER_SUFFIX
)


def _template(name: str) -> str:
    return json.dumps({"Resources": {"R": {"Type": "AWS::ECR::Repository",
                                            "Properties": {"RepositoryName": name}}}})


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 180.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within "
                          f"{timeout_s}s (last={last!r})")


def _resource_failure_reason(cfn, stack_name: str, logical_id: str) -> str:
    """The *_FAILED event's own reason for one logical id."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            if (
                event.get("LogicalResourceId") == logical_id
                and event.get("ResourceStatus", "").endswith("_FAILED")
                and event.get("ResourceStatusReason")
            ):
                return event["ResourceStatusReason"]
    raise AssertionError(f"no *_FAILED event with a reason found for logical id {logical_id!r}")


def _delete_stack(cfn, stack_name: str, timeout_s: float = 180.0) -> None:
    """Delete the stack; a stack that never provisioned anything can vanish (not just reach
    DELETE_COMPLETE) before the first poll, which DescribeStacks reports as a ValidationError."""
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                return
            raise
        if status in _TERMINAL_STATES:
            break
        time.sleep(2)
    assert status == "DELETE_COMPLETE", f"stack {stack_name} failed to delete: {status!r}"


def _masked(reason: str) -> str:
    """The reason with only its per-request token replaced by a fixed placeholder."""
    return _REQUEST_TOKEN.sub("(RequestToken: <token>", reason)


def _assert_nothing_provisioned(cfn, stack_name: str, label: str) -> None:
    """The refused stack lists its one resource with no physical id: nothing was created."""
    summaries = []
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack_name):
        summaries.extend(page["StackResourceSummaries"])
    assert [r["LogicalResourceId"] for r in summaries] == ["R"], (
        f"{label}: expected the one logical resource 'R', got {summaries!r}"
    )
    physical = summaries[0].get("PhysicalResourceId", "")
    assert physical == "", f"{label}: a refused create must mint no physical id, got {physical!r}"


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An ECR::Repository whose RepositoryName violates minLength, maxLength or pattern is
    refused with the registry's own schema-violation message and creates nothing; the same
    template under a legal name reaches CREATE_COMPLETE.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html
    """
    cfn = ctx.client("cloudformation")
    ecr = ctx.client("ecr")
    valid_name = ctx.unique_name("sim2real-behav-ecr-")

    # --- positive control: a legal name deploys ---------------------------------------------
    stack_ok = ctx.unique_name("sim2real-behav-ecr-ok-stack-")
    cfn.create_stack(StackName=stack_ok, TemplateBody=_template(valid_name))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_ok))
    status = _wait_terminal(cfn, stack_ok)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    repos = ecr.describe_repositories(repositoryNames=[valid_name])["repositories"]
    assert [r["repositoryName"] for r in repos] == [valid_name], (
        f"control repository {valid_name!r} must exist, got {repos!r}"
    )

    # --- pattern violation: an uppercase letter is outside the lowercase character class -------
    pattern_name = valid_name.upper()
    stack_pattern = ctx.unique_name("sim2real-behav-ecr-pat-stack-")
    cfn.create_stack(StackName=stack_pattern, TemplateBody=_template(pattern_name))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_pattern))
    status = _wait_terminal(cfn, stack_pattern)
    assert status == "ROLLBACK_COMPLETE", f"pattern violation: expected ROLLBACK_COMPLETE, got {status!r}"
    reason = _resource_failure_reason(cfn, stack_pattern, "R")
    assert _masked(reason) == _PATTERN_REASON, f"pattern violation reason: {reason!r}"
    _assert_nothing_provisioned(cfn, stack_pattern, "pattern violation")

    # --- maxLength violation: one character past the 256-character ceiling --------------------
    maxlen_name = valid_name + "a" * (257 - len(valid_name))
    assert len(maxlen_name) == 257, maxlen_name
    stack_maxlen = ctx.unique_name("sim2real-behav-ecr-maxlen-stack-")
    cfn.create_stack(StackName=stack_maxlen, TemplateBody=_template(maxlen_name))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_maxlen))
    status = _wait_terminal(cfn, stack_maxlen)
    assert status == "ROLLBACK_COMPLETE", f"maxLength violation: expected ROLLBACK_COMPLETE, got {status!r}"
    reason = _resource_failure_reason(cfn, stack_maxlen, "R")
    assert _masked(reason) == _MAXLEN_REASON, f"maxLength violation reason: {reason!r}"
    _assert_nothing_provisioned(cfn, stack_maxlen, "maxLength violation")

    # --- minLength violation: one character short of the 2-character floor --------------------
    minlen_name = "q"
    stack_minlen = ctx.unique_name("sim2real-behav-ecr-minlen-stack-")
    cfn.create_stack(StackName=stack_minlen, TemplateBody=_template(minlen_name))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_minlen))
    status = _wait_terminal(cfn, stack_minlen)
    assert status == "ROLLBACK_COMPLETE", f"minLength violation: expected ROLLBACK_COMPLETE, got {status!r}"
    reason = _resource_failure_reason(cfn, stack_minlen, "R")
    assert _masked(reason) == _MINLEN_REASON, f"minLength violation reason: {reason!r}"
    _assert_nothing_provisioned(cfn, stack_minlen, "minLength violation")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

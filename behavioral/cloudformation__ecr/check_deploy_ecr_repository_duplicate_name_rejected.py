"""deploy-ecr-repository-duplicate-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecr-repository-duplicate-name-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}
_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _template(repo_name: str) -> str:
    return json.dumps({
        "Resources": {
            "Repo": {
                "Type": "AWS::ECR::Repository",
                "Properties": {"RepositoryName": repo_name},
            }
        }
    })


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within "
                          f"{timeout_s}s (last={last!r})")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::ECR::Repository whose name already exists fails pre-deployment name-conflict
    validation, leaving the existing repository untouched; the template under a free name deploys.
    """
    cfn = ctx.client("cloudformation")
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-behav-ecr-dup-")
    free_name = ctx.unique_name("sim2real-behav-ecr-free-")
    stack_name = ctx.unique_name("sim2real-behav-ecr-dup-stack-")
    control_stack = ctx.unique_name("sim2real-behav-ecr-free-stack-")

    ecr.create_repository(repositoryName=repo_name, tags=_TAGS)
    ctx.on_cleanup(_teardown(
        lambda: ecr.delete_repository(repositoryName=repo_name, force=True), "RepositoryNotFoundException"
    ))
    existing = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"][0]

    # Positive control: the identical template under a name nobody holds.
    cfn.create_stack(StackName=control_stack, TemplateBody=_template(free_name), Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_stack(cfn, control_stack))
    status = _wait_terminal(cfn, control_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    control = ecr.describe_repositories(repositoryNames=[free_name])["repositories"][0]
    assert control["repositoryName"] == free_name, f"control repository: {control!r}"

    # The one thing broken: the repository name is already taken.
    cfn.create_stack(StackName=stack_name, TemplateBody=_template(repo_name), Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    status = _wait_terminal(cfn, stack_name)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    stack_failed_reasons = [
        e.get("ResourceStatusReason", "") for e in events
        if e.get("LogicalResourceId") == stack_name and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert stack_failed_reasons == [_STACK_REASON], (
        f"expected the stack's CREATE_FAILED reason to be {_STACK_REASON!r}, got {stack_failed_reasons!r}"
    )
    found = _validation_errors(cfn, stack_name)
    want = [(
        "Repo", "AWS::ECR::Repository", "NAME_CONFLICT_VALIDATION", "FAILED", "FAIL",
        f"Resource of type 'AWS::ECR::Repository' with identifier '{repo_name}' already exists.",
        "/Resources/Repo",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert resources == [], (
        f"a stack rejected before provisioning must report no resources, got {resources!r}"
    )

    after = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"][0]
    kept = ("repositoryArn", "createdAt", "imageTagMutability")
    assert {k: after[k] for k in kept} == {k: existing[k] for k in kept}, (
        f"the pre-existing repository changed: before {existing!r}, after {after!r}"
    )

    for name in (stack_name, control_stack):
        _delete_stack(cfn, name)
        got = _error(lambda name=name: cfn.describe_stacks(StackName=name))
        assert got == ("ValidationError", f"Stack with id {name} does not exist"), (
            f"DescribeStacks after the delete of {name}: {got!r}"
        )
    got = _error(lambda: ecr.describe_repositories(repositoryNames=[free_name]))
    want_gone = (
        "RepositoryNotFoundException",
        f"The repository with name '{free_name}' does not exist in the registry with id '{ctx.account}'",
    )
    assert got == want_gone, f"the control repository after its stack delete: {got!r}"


def _validation_errors(cfn, stack_name: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason, path)`` of each VALIDATION_ERROR operation event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"),
                    e.get("ValidationPath"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

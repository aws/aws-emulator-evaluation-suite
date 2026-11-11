"""deploy-cfn-ecr-repository-policy-restricts-cross-account-pull-rejected."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-ecr-repository-policy-restricts-cross-account-pull-rejected"
GROUP = "iac-stack"
SERVICES = ["cloudwatch", "ecr", "ecs"]


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed ECR repository policy is enforced: a caller-scoped Deny rejects TagResource
    with AccessDeniedException and no tag lands; with only the PrincipalAccount-guarded pull Deny
    left, the same call succeeds. The stack's ECS task definition uses the repository's image URI.
    """
    ecr = ctx.client("ecr")
    ecs = ctx.client("ecs")
    identity = ctx.client("sts").get_caller_identity()
    account_id = identity["Account"]
    caller_role_arn = _principal_role_arn(identity["Arn"], account_id)

    repo_name = _xname(ctx, "repo")
    family_name = _xname(ctx, "taskdef")

    # CloudFormation only deregisters a TaskDefinition resource on stack delete (INACTIVE), never
    # deletes the revision -- registered LAST so it pops (runs) AFTER the stack's own on_cleanup.
    task_def_arn_holder: list[str] = []
    ctx.on_cleanup(lambda: _delete_task_def_revision(ecs, task_def_arn_holder))

    deny_foreign_pull = {
        "Sid": "DenyForeignAccountPull",
        "Effect": "Deny",
        "Principal": "*",
        "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
        "Condition": {"StringNotEquals": {"aws:PrincipalAccount": account_id}},
    }
    # A foreign principal cannot be authenticated here, so enforcement is proven with a Deny scoped
    # to the caller's own principal for a distinct action (TagResource).
    deny_caller_tag = {
        "Sid": "DenyCallerTag",
        "Effect": "Deny",
        "Principal": {"AWS": caller_role_arn},
        "Action": ["ecr:TagResource"],
    }
    full_policy = {"Version": "2012-10-17", "Statement": [deny_foreign_pull, deny_caller_tag]}

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Repository": {
                "Type": "AWS::ECR::Repository",
                "Properties": {
                    "RepositoryName": repo_name,
                    "RepositoryPolicyText": full_policy,
                },
            },
            "TaskDefinition": {
                "Type": "AWS::ECS::TaskDefinition",
                "DependsOn": ["Repository"],
                "Properties": {
                    "Family": family_name,
                    "ContainerDefinitions": [
                        {
                            "Name": "app",
                            "Image": {
                                "Fn::Sub": (
                                    "${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/"
                                    + repo_name
                                    + ":latest"
                                )
                            },
                            "Memory": 128,
                        }
                    ],
                },
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template), timeout_s=120.0)

    # resource_reference edge: the task definition's container image really is this repo's URI.
    task_def = ecs.describe_task_definition(taskDefinition=family_name)["taskDefinition"]
    task_def_arn_holder.append(task_def["taskDefinitionArn"])
    # The image is <account>.dkr.ecr.<region>.<domain>/<repo>:latest; the domain is the target's.
    actual_image = task_def["containerDefinitions"][0]["image"]
    host, _, path = actual_image.partition("/")
    labels = host.split(".")
    assert (labels[:4] == [account_id, "dkr", "ecr", ctx.region] and len(labels) > 4
            and all(labels[4:]) and path == f"{repo_name}:latest"), (
        f"expected task def image {account_id}.dkr.ecr.{ctx.region}.<domain>/{repo_name}:latest, "
        f"got {actual_image!r}")

    # The cross-account-restricting Deny persisted verbatim -- the "restricts cross-account pull"
    # shape: Principal "*" narrowed by a PrincipalAccount condition (ECR validates that any
    # account referenced BY ARN in Principal actually exists, so account-scoping must go through
    # the Condition block rather than naming a foreign account ARN directly).
    persisted = json.loads(ecr.get_repository_policy(repositoryName=repo_name)["policyText"])
    foreign_stmt = next(s for s in persisted["Statement"] if s["Sid"] == "DenyForeignAccountPull")
    assert foreign_stmt["Effect"] == "Deny", f"expected Deny, got {foreign_stmt['Effect']!r}"
    persisted_condition_account = foreign_stmt["Condition"]["StringNotEquals"]["aws:PrincipalAccount"]
    assert persisted_condition_account == account_id, (
        f"expected PrincipalAccount condition pinned to {account_id!r}, got {persisted_condition_account!r}"
    )

    # --- Negative: the caller's own principal is explicitly denied TagResource -> rejected.
    got = _error(
        lambda: ecr.tag_resource(
            resourceArn=task_def_repo_arn(account_id, ctx.region, repo_name),
            tags=[{"Key": "probe", "Value": "denied"}],
        )
    )
    want = (
        "AccessDeniedException",
        f"User: {identity['Arn']} is not authorized to perform: ecr:TagResource on resource: "
        f"{task_def_repo_arn(account_id, ctx.region, repo_name)} with an explicit deny in a "
        "resource-based policy",
    )
    assert got == want, f"TagResource under the caller-scoped Deny raised {got!r}, expected {want!r}"

    # Effect absent: the tag never landed.
    tags_after_deny = ecr.list_tags_for_resource(
        resourceArn=task_def_repo_arn(account_id, ctx.region, repo_name)
    )["tags"]
    assert not any(t["Key"] == "probe" for t in tags_after_deny), "denied TagResource still tagged the repo"

    # --- Positive control: remove ONLY the caller-scoped Deny (foreign-account Deny stays put),
    # and the identical call now succeeds.
    narrowed_policy = {"Version": "2012-10-17", "Statement": [deny_foreign_pull]}
    ecr.set_repository_policy(repositoryName=repo_name, policyText=json.dumps(narrowed_policy))

    # The foreign-account Deny is still there, untouched by narrowing the policy.
    still_persisted = json.loads(ecr.get_repository_policy(repositoryName=repo_name)["policyText"])
    assert any(s["Sid"] == "DenyForeignAccountPull" for s in still_persisted["Statement"]), (
        "narrowing the policy to drop DenyCallerTag lost DenyForeignAccountPull too"
    )

    ecr.tag_resource(
        resourceArn=task_def_repo_arn(account_id, ctx.region, repo_name),
        tags=[{"Key": "probe", "Value": "allowed"}],
    )
    tags_after_allow = ecr.list_tags_for_resource(
        resourceArn=task_def_repo_arn(account_id, ctx.region, repo_name)
    )["tags"]
    assert any(t["Key"] == "probe" and t["Value"] == "allowed" for t in tags_after_allow), (
        "control tag call succeeded but the tag is missing"
    )


def task_def_repo_arn(account_id: str, region: str, repo_name: str) -> str:
    return f"arn:aws:ecr:{region}:{account_id}:repository/{repo_name}"


def _principal_role_arn(caller_arn: str, account_id: str) -> str:
    """The IAM role ARN behind an assumed-role session ARN, since a resource-policy Principal must
    name the ROLE, not the session; any other caller ARN is returned unchanged."""
    marker = ":assumed-role/"
    if marker not in caller_arn:
        return caller_arn
    after = caller_arn.split(marker, 1)[1]
    role_name = after.split("/", 1)[0]
    return f"arn:aws:iam::{account_id}:role/{role_name}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_task_def_revision(ecs, task_def_arn_holder: list[str]) -> None:
    """Delete the task def revision this check registered (via CFN) once it is INACTIVE. CFN's
    own stack-delete cleanup only deregisters it; DeleteTaskDefinitions is the only way to make the
    revision stop listing. No-op if the body never got far enough to record an ARN."""
    if not task_def_arn_holder:
        return
    arn = task_def_arn_holder[0]

    def _status():
        try:
            return ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
        except ClientError as exc:
            if "Unable to describe task definition" not in exc.response["Error"].get("Message", ""):
                raise
            return "GONE"

    status = _poll_until(
        _status,
        lambda s: s in {"INACTIVE", "GONE"},
        timeout_s=60.0,
        interval_s=2.0,
        description=f"task def {arn} deregistration",
    )
    if status == "GONE":
        return
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        events = cfn.describe_stack_events(StackName=name)["StackEvents"]
        reasons = "; ".join(
            f"{e.get('LogicalResourceId')}:{e.get('ResourceStatus')}:{e.get('ResourceStatusReason', '')}"
            for e in events
        )
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}: {reasons[:2000]}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS denies is the strongest signal available and
    must not be reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

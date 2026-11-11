"""deploy-notebook-instance-cfn-presigned-url-works."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)



CHECK = "deploy-notebook-instance-cfn-presigned-url-works"
GROUP = "deploy"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A NotebookInstance deployed via CloudFormation reaches InService, and a presigned
    URL generated against it is actually accepted by the notebook's HTTPS front door --
    proving the CFN-provisioned resource is usable, not just CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")

    role_arn = _create_sagemaker_role(ctx)

    notebook_name = ctx.unique_name("sim2real-nb-")
    stack_name = ctx.unique_name("sim2real-nb-stack-")
    template = json.dumps(
        {
            "Resources": {
                "Notebook": {
                    "Type": "AWS::SageMaker::NotebookInstance",
                    "Properties": {
                        "NotebookInstanceName": notebook_name,
                        "InstanceType": "ml.t3.medium",
                        "RoleArn": role_arn,
                    },
                }
            }
        }
    )

    _deploy_cfn(ctx, cfn, stack_name, template)

    status = _poll_until(
        probe=lambda: sm.describe_notebook_instance(NotebookInstanceName=notebook_name)["NotebookInstanceStatus"],
        predicate=lambda s: s in ("InService", "Failed"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert status == "InService", f"notebook instance did not reach InService (status={status!r})"

    url = sm.create_presigned_notebook_instance_url(NotebookInstanceName=notebook_name)["AuthorizedUrl"]
    assert not (p := ctx.published_url_mismatch(url, labels=("notebook", ctx.region, "sagemaker"))), p

    try:
        with urllib.request.urlopen(_routed_request(ctx, url), timeout=30) as resp:
            status_code = resp.status
    except urllib.error.HTTPError as exc:
        status_code = exc.code
    assert status_code < 400, f"presigned notebook URL was not accepted, HTTP status {status_code}"


# ===== helpers =====
def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
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


def _is_role_not_yet_usable(reasons: list[str]) -> bool:
    text = " ".join(reasons).lower()
    return "role" in text and (
        "not authorized" in text
        or "cannot be assumed" in text
        or "is invalid" in text
        or "does not exist" in text
    )


def _deploy_cfn(ctx, cfn, stack_name: str, template: str, *, max_attempts: int = 4) -> None:
    """A role IAM just created may not yet be assumable everywhere SageMaker checks it, so the
    NotebookInstance resource inside the stack can fail CREATE with a role/assume-role error even
    though CreateStack itself accepted the request. CloudFormation gives a failed resource no
    built-in retry, so retry the whole stack (a fresh name each time, since a failed stack cannot
    be re-created under the same one) bounded by max_attempts; any other failure reason is not
    retried."""
    last_reasons: list[str] = []
    for attempt in range(1, max_attempts + 1):
        this_stack = stack_name if attempt == 1 else f"{stack_name}-r{attempt}"
        cfn.create_stack(
            StackName=this_stack,
            TemplateBody=template,
            Capabilities=["CAPABILITY_IAM"],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

        def _cleanup(s=this_stack):
            try:
                cfn.delete_stack(StackName=s)
                cfn.get_waiter("stack_delete_complete").wait(
                    StackName=s, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                    exc.response["Error"]["Code"] == "ValidationError"
                    and "does not exist" not in exc.response["Error"]["Message"]
                ):
                    raise

        ctx.on_cleanup(_cleanup)
        try:
            cfn.get_waiter("stack_create_complete").wait(
                StackName=this_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
            )
            return
        except Exception as exc:
            events = cfn.describe_stack_events(StackName=this_stack)["StackEvents"]
            last_reasons = [
                f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
                for e in events
                if e.get("ResourceStatus", "").endswith("FAILED")
            ]
            if _is_role_not_yet_usable(last_reasons) and attempt < max_attempts:
                # The failed attempt itself spans minutes of role propagation; retry promptly.
                time.sleep(2)
                continue
            raise AssertionError(f"stack {this_stack!r} failed to create: {last_reasons or exc}") from exc
    raise AssertionError(f"stack never created cleanly after {max_attempts} attempts: {last_reasons}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

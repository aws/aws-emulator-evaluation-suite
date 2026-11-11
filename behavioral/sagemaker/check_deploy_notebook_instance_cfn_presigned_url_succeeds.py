"""deploy-notebook-instance-cfn-presigned-url-succeeds."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "deploy-notebook-instance-cfn-presigned-url-succeeds"
GROUP = "deploy"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A NotebookInstance deployed via CloudFormation is usable: once the stack is
    CREATE_COMPLETE, CreatePresignedNotebookInstanceUrl returns a URL the notebook's HTTPS
    front door accepts, not merely a control-plane echo of the template."""
    cf = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    stack_name = ctx.unique_name("sim2real-nbi-stack-")
    notebook_name = ctx.unique_name("sim2real-nbi-")
    role_logical_id = "NotebookExecutionRole"
    notebook_logical_id = "Notebook"

    template = {
        "Resources": {
            role_logical_id: {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "sagemaker.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
                    ],
                },
            },
            notebook_logical_id: {
                "Type": "AWS::SageMaker::NotebookInstance",
                "Properties": {
                    "NotebookInstanceName": notebook_name,
                    "InstanceType": "ml.t3.medium",
                    "RoleArn": {"Fn::GetAtt": [role_logical_id, "Arn"]},
                },
            },
        }
    }

    _deploy_cfn(ctx, cf, stack_name, template)

    _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=notebook_name)[
            "NotebookInstanceStatus"
        ],
        lambda status: status == "InService",
        timeout_s=900.0,
        interval_s=15.0,
    )

    presigned = sm.create_presigned_notebook_instance_url(NotebookInstanceName=notebook_name)
    url = presigned["AuthorizedUrl"]
    assert not (p := ctx.published_url_mismatch(url, labels=("notebook", ctx.region, "sagemaker"))), p
    assert notebook_name in url, url
    assert "authToken=" in url, url

    # The URL's own shape proves nothing about the deployed instance -- confirm it is actually
    # accepted by the notebook's real HTTPS front door, not merely well-formed.
    try:
        with urllib.request.urlopen(_routed_request(ctx, url), timeout=30) as resp:
            status_code = resp.status
    except urllib.error.HTTPError as exc:
        status_code = exc.code
    assert status_code < 400, f"presigned notebook URL was not accepted, HTTP status {status_code}"


# ===== helpers =====
def _deploy_cfn(ctx, cf, stack_name: str, template: dict) -> None:
    cf.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_name))
    waiter = cf.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})


def _delete_stack(cf, stack_name: str) -> None:
    cf.delete_stack(StackName=stack_name)
    waiter = cf.get_waiter("stack_delete_complete")
    # Bounded by the suite's cleanup budget.
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 570})


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

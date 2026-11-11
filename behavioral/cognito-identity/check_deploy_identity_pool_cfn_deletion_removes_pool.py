"""deploy-identity-pool-cfn-deletion-removes-pool."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-identity-pool-cfn-deletion-removes-pool"
GROUP = "deploy"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Deleting the CFN stack actually removes the underlying identity pool, verified by a
    subsequent DescribeIdentityPool ResourceNotFoundException rather than trusting the stack's
    DELETE_COMPLETE status alone."""
    pool_name = ctx.unique_name("sim2real_cog_pool_")
    template = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  IdentityPool:
    Type: AWS::Cognito::IdentityPool
    Properties:
      IdentityPoolName: {pool_name}
      AllowUnauthenticatedIdentities: false
Outputs:
  IdentityPoolIdOut:
    Value: !Ref IdentityPool
"""
    deployed = _deploy_cfn(ctx, template)
    pool_id = deployed["outputs"]["IdentityPoolIdOut"]
    stack_name = deployed["stack_name"]

    cognito = ctx.client("cognito-identity")

    # positive control: the pool genuinely exists right after CREATE_COMPLETE.
    desc = cognito.describe_identity_pool(IdentityPoolId=pool_id)
    assert desc["IdentityPoolId"] == pool_id, (
        f"expected the freshly created pool {pool_id!r} to describe itself, got {desc.get('IdentityPoolId')!r}"
    )

    _delete_stack_and_wait(ctx, stack_name)

    not_found = ("ResourceNotFoundException", f"IdentityPool '{pool_id}' not found.")
    code = _poll_until(
        lambda: _describe_outcome(cognito, pool_id),
        lambda c: c != _EXISTS,
        timeout_s=60,
        interval_s=3.0,
        description="pool removed after stack deletion",
    )
    assert code == not_found, (
        f"expected {not_found!r} from describe_identity_pool on {pool_id!r} "
        f"after stack deletion, got {code!r}"
    )

    # the pool is not just absent from a read: it is unusable for a mutation too.
    try:
        cognito.update_identity_pool(
            IdentityPoolId=pool_id,
            IdentityPoolName=pool_name,
            AllowUnauthenticatedIdentities=False,
        )
    except ClientError as e:
        mutate_code = e.response["Error"]["Code"], e.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"expected update_identity_pool on deleted pool {pool_id!r} to fail, but it succeeded"
        )
    assert mutate_code == not_found, (
        f"expected {not_found!r} from update_identity_pool on deleted pool "
        f"{pool_id!r}, got {mutate_code!r}"
    )


_EXISTS = "pool-still-describes"


def _describe_outcome(cognito, pool_id):
    """DescribeIdentityPool's (Code, Message) once it fails, or _EXISTS (which no error tuple
    equals) while the pool still describes."""
    try:
        cognito.describe_identity_pool(IdentityPoolId=pool_id)
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return _EXISTS


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _xsvc_tags_kv():
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")},
    ]


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0):
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

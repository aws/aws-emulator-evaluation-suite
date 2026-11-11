"""deploy-identity-pool-cfn-stack-update-changes-runtime-behavior."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-identity-pool-cfn-stack-update-changes-runtime-behavior"
GROUP = "deploy"
SERVICES = ["cognito-identity"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  PoolName:
    Type: String
  AllowUnauth:
    Type: String
    AllowedValues:
      - "true"
      - "false"
Resources:
  IdentityPool:
    Type: AWS::Cognito::IdentityPool
    Properties:
      IdentityPoolName: !Ref PoolName
      AllowUnauthenticatedIdentities: !Ref AllowUnauth
Outputs:
  PoolId:
    Value: !Ref IdentityPool
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Updating AllowUnauthenticatedIdentities via a CFN stack update flips live GetId
    acceptance behavior in place, without replacing the underlying identity pool, and flipping
    it back restores the original behavior on the same pool."""
    cfn = ctx.client("cloudformation")
    cognito = ctx.client("cognito-identity")
    stack_name = ctx.unique_name("sim2real-behav-cipupd-")
    pool_name = ctx.unique_name("sim2real-behav-pool-")

    def _params(allow_unauth: str) -> list[dict]:
        return [
            {"ParameterKey": "PoolName", "ParameterValue": pool_name},
            {"ParameterKey": "AllowUnauth", "ParameterValue": allow_unauth},
        ]

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=_params("true"),
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    pool_id = _stack_outputs(cfn, stack_name)["PoolId"]

    # Positive control: AllowUnauthenticatedIdentities=true -> anonymous GetId succeeds.
    first = cognito.get_id(IdentityPoolId=pool_id)
    assert first.get("IdentityId"), f"positive control: expected an IdentityId, got {first!r}"

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=_params("false"),
    )
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    pool_id_disabled = _stack_outputs(cfn, stack_name)["PoolId"]
    assert pool_id_disabled == pool_id, (
        f"stack update replaced the pool instead of updating it in place: "
        f"before={pool_id!r} after={pool_id_disabled!r}"
    )

    desc = cognito.describe_identity_pool(IdentityPoolId=pool_id_disabled)
    assert desc["AllowUnauthenticatedIdentities"] is False, (
        f"expected AllowUnauthenticatedIdentities=False after update, got {desc['AllowUnauthenticatedIdentities']!r}"
    )

    err = _error(lambda: cognito.get_id(IdentityPoolId=pool_id_disabled))
    expected = (
        "NotAuthorizedException",
        "Unauthenticated access is not supported for this identity pool.",
    )
    assert err == expected, (
        f"expected {expected!r} for anonymous GetId once unauth access is disabled, got {err!r}"
    )

    # Restore leg: flip the same stack back to true and demand the identical call succeeds again
    # on the SAME pool -- proving the flip is a live, reversible in-place update, not a one-way trip.
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=_params("true"),
    )
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    pool_id_restored = _stack_outputs(cfn, stack_name)["PoolId"]
    assert pool_id_restored == pool_id, (
        f"restore update replaced the pool instead of updating it in place: "
        f"before={pool_id!r} restored={pool_id_restored!r}"
    )

    desc_restored = cognito.describe_identity_pool(IdentityPoolId=pool_id_restored)
    assert desc_restored["AllowUnauthenticatedIdentities"] is True, (
        f"expected AllowUnauthenticatedIdentities=True after restore, got {desc_restored['AllowUnauthenticatedIdentities']!r}"
    )

    # The flag reads back before GetId honours it, so poll (bounded) for the restored GetId.
    restored = _get_id_when_allowed(cognito, pool_id_restored)
    assert restored.get("IdentityId"), (
        f"restore control: expected anonymous GetId to succeed again, got {restored!r}"
    )


def _stack_outputs(cfn, stack_name):
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


def _get_id_when_allowed(cognito, pool_id, timeout_s=60.0, interval_s=3.0):
    """Anonymous GetId, retried only while the re-enabled flag is still propagating."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cognito.get_id(IdentityPoolId=pool_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotAuthorizedException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

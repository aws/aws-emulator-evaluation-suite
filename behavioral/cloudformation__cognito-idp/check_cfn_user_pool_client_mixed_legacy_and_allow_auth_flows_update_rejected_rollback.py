"""cfn-user-pool-client-mixed-legacy-and-allow-auth-flows-update-rejected-rollback."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "cfn-user-pool-client-mixed-legacy-and-allow-auth-flows-update-rejected-rollback"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "cognito-idp"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _delete_stack(cf, stack_id):
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def _paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``."""
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return _paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def _template(*, pool_name: str, client_name: str, explicit_auth_flows: list[str],
             refresh_token_validity: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": pool_name,
                    "DeletionProtection": "INACTIVE",
                },
            },
            "PoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": client_name,
                    "UserPoolId": {"Ref": "Pool"},
                    "ExplicitAuthFlows": explicit_auth_flows,
                    "RefreshTokenValidity": refresh_token_validity,
                },
            },
        },
        "Outputs": {
            "PoolRef": {"Value": {"Ref": "Pool"}},
            "ClientRef": {"Value": {"Ref": "PoolClient"}},
        },
    })


def _outputs(cf, stack_id) -> dict:
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _masked(text: str) -> str:
    """``text`` with only the opaque, per-call request identifiers blanked out."""
    text = re.sub(r"Request ID: [^,;)]+", "Request ID: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <id>", text)
    return text


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN update to AWS::Cognito::UserPoolClient naming a legacy ExplicitAuthFlows value
    (ADMIN_NO_SRP_AUTH) together with an ALLOW_-prefixed one rolls back, leaving the client's
    original auth flows and ClientId untouched.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    stack_name = ctx.unique_name("sim2real-behav-cogclientmix-")
    pool_name = ctx.unique_name("sim2real-behav-cogclientmixpool-")
    client_name = ctx.unique_name("sim2real-behav-cogclientmixclient-")
    original_flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(
            pool_name=pool_name, client_name=client_name,
            explicit_auth_flows=original_flows, refresh_token_validity=30,
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    outputs = _outputs(cfn, stack_id)
    pool_id = outputs["PoolRef"]
    client_id = outputs["ClientRef"]

    baseline = cognito.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id
    )["UserPoolClient"]
    assert sorted(baseline["ExplicitAuthFlows"]) == sorted(original_flows), (
        f"expected ExplicitAuthFlows {sorted(original_flows)!r}, "
        f"got {sorted(baseline['ExplicitAuthFlows'])!r}"
    )

    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(
            pool_name=pool_name, client_name=client_name,
            explicit_auth_flows=["ADMIN_NO_SRP_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
            refresh_token_validity=99,
        ),
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"mixed-auth-flows update ended {status!r}"

    failed = [
        (e["LogicalResourceId"], _masked(e.get("ResourceStatusReason") or ""))
        for e in _stack_events(cfn, stack_id)
        if e["ResourceStatus"] == "UPDATE_FAILED"
    ]
    expected_reason = (
        'Resource handler returned message: "Auth flow name with prefix \'ALLOW\' cannot be '
        "used with legacy auth flow names. (Service: CognitoIdentityProvider, Status Code: 400, "
        'Request ID: <id>) (SDK Attempt Count: <n>)" '
        "(RequestToken: <id>, HandlerErrorCode: InvalidRequest)"
    )
    assert failed == [("PoolClient", expected_reason)], (
        f"expected exactly one UPDATE_FAILED event on PoolClient with reason "
        f"{expected_reason!r}, got {failed!r}"
    )

    after = cognito.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id
    )["UserPoolClient"]
    assert after["ClientId"] == client_id, (
        f"the rolled-back update should not replace the client: "
        f"expected ClientId {client_id!r}, got {after['ClientId']!r}"
    )
    assert sorted(after["ExplicitAuthFlows"]) == sorted(original_flows), (
        f"the rolled-back update should leave ExplicitAuthFlows at {sorted(original_flows)!r}, "
        f"got {sorted(after['ExplicitAuthFlows'])!r}"
    )
    assert after["RefreshTokenValidity"] == 30, (
        f"the rolled-back update should leave RefreshTokenValidity at 30, "
        f"got {after['RefreshTokenValidity']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

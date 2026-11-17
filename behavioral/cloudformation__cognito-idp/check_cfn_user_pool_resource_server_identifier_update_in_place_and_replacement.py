"""cfn-user-pool-resource-server-identifier-update-in-place-and-replacement."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-user-pool-resource-server-identifier-update-in-place-and-replacement"
GROUP = "deploy"
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


def _outputs(cf, stack_id) -> dict:
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(*, pool_name: str, identifier: str, name: str, scopes: list[dict]) -> str:
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
            "ResourceServer": {
                "Type": "AWS::Cognito::UserPoolResourceServer",
                "Properties": {
                    "UserPoolId": {"Ref": "Pool"},
                    "Identifier": identifier,
                    "Name": name,
                    "Scopes": scopes,
                },
            },
        },
        "Outputs": {
            "PoolRef": {"Value": {"Ref": "Pool"}},
            "ResourceServerRef": {"Value": {"Ref": "ResourceServer"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN update changing only Name keeps a UserPoolResourceServer's declared Identifier; one
    changing Identifier replaces it under the new Identifier, carrying the latest Name and Scopes,
    and the old Identifier is gone.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolresourceserver.html
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    stack_name = ctx.unique_name("sim2real-behav-cogrsid-")
    pool_name = ctx.unique_name("sim2real-behav-cogrsidpool-")
    identifier_a = f"https://{ctx.unique_name('sim2real-behav-cogrsid-a-')}.example.com"
    identifier_b = f"https://{ctx.unique_name('sim2real-behav-cogrsid-b-')}.example.com"
    name_1 = ctx.unique_name("sim2real-behav-cogrsidname1-")
    name_2 = ctx.unique_name("sim2real-behav-cogrsidname2-")
    scopes = [{"ScopeName": "read", "ScopeDescription": "read scope"}]

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(
            pool_name=pool_name, identifier=identifier_a, name=name_1, scopes=scopes
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    outputs = _outputs(cfn, stack_id)
    pool_id = outputs["PoolRef"]
    assert outputs["ResourceServerRef"] == identifier_a, (
        f"expected Ref to equal the declared Identifier {identifier_a!r}, "
        f"got {outputs['ResourceServerRef']!r}"
    )

    server = cognito.describe_resource_server(
        UserPoolId=pool_id, Identifier=identifier_a
    )["ResourceServer"]
    assert server["Name"] == name_1, f"expected Name {name_1!r}, got {server['Name']!r}"

    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(
            pool_name=pool_name, identifier=identifier_a, name=name_2, scopes=scopes
        ),
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"in-place update ended {status!r}"

    outputs = _outputs(cfn, stack_id)
    assert outputs["ResourceServerRef"] == identifier_a, (
        f"a Name-only update should keep Identifier {identifier_a!r}, "
        f"got {outputs['ResourceServerRef']!r}"
    )
    renamed = cognito.describe_resource_server(
        UserPoolId=pool_id, Identifier=identifier_a
    )["ResourceServer"]
    assert renamed["Name"] == name_2, f"expected the updated Name {name_2!r}, got {renamed['Name']!r}"

    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(
            pool_name=pool_name, identifier=identifier_b, name=name_2, scopes=scopes
        ),
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"replacement update ended {status!r}"

    outputs = _outputs(cfn, stack_id)
    assert outputs["ResourceServerRef"] == identifier_b, (
        f"changing Identifier should replace the resource server under {identifier_b!r}, "
        f"got {outputs['ResourceServerRef']!r}"
    )

    replaced = cognito.describe_resource_server(
        UserPoolId=pool_id, Identifier=identifier_b
    )["ResourceServer"]
    assert replaced["Name"] == name_2, (
        f"the replacement should carry the latest Name {name_2!r}, got {replaced['Name']!r}"
    )
    assert replaced["Scopes"] == scopes, (
        f"the replacement should carry the declared Scopes {scopes!r}, got {replaced['Scopes']!r}"
    )

    server_a_gone = (
        "ResourceNotFoundException",
        f"{identifier_a} does not exist in user pool {pool_id}.",
    )
    _expect_error(
        lambda: cognito.describe_resource_server(UserPoolId=pool_id, Identifier=identifier_a),
        *server_a_gone,
    )

    _delete_stack(cfn, stack_id)

    pool_gone = ("ResourceNotFoundException", f"User pool {pool_id} does not exist.")
    _expect_error(lambda: cognito.describe_user_pool(UserPoolId=pool_id), *pool_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

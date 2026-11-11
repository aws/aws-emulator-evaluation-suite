"""customer-managed-permission-resource-type-restriction-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "customer-managed-permission-resource-type-restriction-rejected"
GROUP = "permission-lifecycle"
SERVICES = ["ram"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePermission refuses a resource type that has no customer-managed-permission
    support (ec2:Subnet), while a type that does (codebuild:Project) still succeeds."""
    ram = ctx.client("ram")

    name = ctx.unique_name("sim2real-ram-perm-")
    policy = json.dumps({"Effect": "Allow", "Action": ["ec2:DescribeSubnets"]})
    code, message = _error(
        lambda: ram.create_permission(
            name=name, resourceType="ec2:Subnet", policyTemplate=policy
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}: {message!r}"
    assert message == "Customer managed permission is not supported for resource type ec2:Subnet", (
        f"unexpected message {message!r}"
    )

    # Positive control: a resource type that DOES support customer-managed permissions
    # accepts the same shape of request, proving CreatePermission itself is healthy.
    supported_policy = json.dumps({"Effect": "Allow", "Action": ["codebuild:BatchGetProjects"]})
    created = ram.create_permission(
        name=name, resourceType="codebuild:Project", policyTemplate=supported_policy,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["permission"]
    perm_arn = created["arn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_permission(permissionArn=perm_arn), "UnknownResourceException")
    )
    got = ram.get_permission(permissionArn=perm_arn)["permission"]
    assert got["permissionType"] == "CUSTOMER_MANAGED", (
        f"expected permissionType CUSTOMER_MANAGED, got {got['permissionType']!r}"
    )

    arns = set()
    next_token = None
    while True:
        kwargs = {"resourceType": "codebuild:Project", "permissionType": "CUSTOMER_MANAGED"}
        if next_token:
            kwargs["nextToken"] = next_token
        page = ram.list_permissions(**kwargs)
        arns.update(p["arn"] for p in page["permissions"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert perm_arn in arns, (
        f"expected {perm_arn!r} among customer-managed codebuild:Project permissions, got {sorted(arns)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

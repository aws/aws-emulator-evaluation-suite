"""create-permission-version-disallowed-action-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-permission-version-disallowed-action-rejected"
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
    """CreatePermissionVersion refuses a policy template naming a mutating action RAM
    never allows a shared-resource permission to grant, and the permission's existing
    version is unaffected by the refused attempt."""
    ram = ctx.client("ram")

    name = ctx.unique_name("sim2real-ram-permver-")
    v1_policy = json.dumps({"Effect": "Allow", "Action": ["codebuild:BatchGetProjects"]})
    created = ram.create_permission(
        name=name, resourceType="codebuild:Project", policyTemplate=v1_policy,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["permission"]
    perm_arn = created["arn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_permission(permissionArn=perm_arn), "UnknownResourceException")
    )

    disallowed_policy = json.dumps({"Effect": "Allow", "Action": ["codebuild:DeleteProject"]})
    code, message = _error(
        lambda: ram.create_permission_version(permissionArn=perm_arn, policyTemplate=disallowed_policy)
    )
    assert code == "InvalidPolicyException", f"expected InvalidPolicyException, got {code}: {message!r}"
    assert message == (
        "InvalidPolicy: Input policy containing action that is not allowed for "
        "resource type codebuild:Project"
    ), f"unexpected message {message!r}"

    # Effect absent: the refused version was never created, so version 1 is still the
    # only and the default version.
    versions = ram.list_permission_versions(permissionArn=perm_arn)["permissions"]
    assert [v["version"] for v in versions] == ["1"], (
        f"expected only version 1 to exist, got {[v['version'] for v in versions]!r}"
    )

    # Positive control: a policy template naming only an allowed, read-only action
    # creates a second version normally, proving CreatePermissionVersion is healthy.
    v2_policy = json.dumps(
        {"Effect": "Allow", "Action": ["codebuild:BatchGetProjects", "codebuild:ListBuildsForProject"]}
    )
    v2 = ram.create_permission_version(permissionArn=perm_arn, policyTemplate=v2_policy)["permission"]
    assert v2["version"] == "2", f"expected version 2, got {v2['version']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

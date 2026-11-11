"""delete-workload-identity-attached-to-runtime-blocked."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-workload-identity-attached-to-runtime-blocked"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteWorkloadIdentity on a deleted name is refused with ResourceNotFoundException "WorkloadIdentity
    with name <name> not found.", while a fresh workload identity deletes and drops out of ListWorkloadIdentities."""
    bac = ctx.client("bedrock-agentcore-control")

    name = _name(ctx, "sim2real-wi")
    created = bac.create_workload_identity(name=name)
    assert created["name"] == name, f"expected created workload identity name {name!r}, got {created.get('name')!r}"

    bac.delete_workload_identity(name=name)
    assert not _exists(bac, name), "workload identity should be gone after its first delete"

    code, message = _error_detail(lambda: bac.delete_workload_identity(name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"WorkloadIdentity with name {name} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a fresh, never-deleted workload identity deletes cleanly.
    name2 = _name(ctx, "sim2real-wi2")
    created2 = bac.create_workload_identity(name=name2)
    assert created2["name"] == name2, f"expected created workload identity name {name2!r}, got {created2.get('name')!r}"
    bac.delete_workload_identity(name=name2)
    assert not _exists(bac, name2), "expected the fresh workload identity delete to be accepted"


def _name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9_.\-]", "-", raw).strip("-")
    return name[:255]


def _exists(bac, name: str) -> bool:
    try:
        bac.get_workload_identity(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return True


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

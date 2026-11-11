"""list-users-invalid-extension-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-users-invalid-extension-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListUsers rejects an Extensions entry that isn't the one supported extension name
    (aws:identitystore:enterprise)."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    bad_extension = "not:a:real:extension"
    err = _error(lambda: idstore.list_users(IdentityStoreId=store_id, Extensions=[bad_extension]))
    expected_message = (
        f"1 validation error detected: Value '[{bad_extension}]' at 'extensions' failed to satisfy "
        "constraint: Member must satisfy constraint: [Member must have length less than or equal to 50, "
        "Member must have length greater than or equal to 1, Member must satisfy regular expression "
        "pattern: aws:identitystore:[a-z]{1,20}, Member must not be null]"
    )
    assert err == ("ValidationException", expected_message), (
        f"expected ValidationException {expected_message!r}, ListUsers returned {err!r}"
    )

    # Positive control: the same call without an unsupported Extensions entry succeeds.
    resp = idstore.list_users(IdentityStoreId=store_id, MaxResults=1)
    assert "Users" in resp, f"expected a Users key in the positive-control ListUsers response, got {resp!r}"


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
    import time

    sso_admin = ctx.client("sso-admin")

    def _ready_id(insts):
        for inst in insts:
            if inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        return None

    instances = sso_admin.list_instances().get("Instances", [])
    found = _ready_id(instances)
    if found:
        return found
    if not instances:
        try:
            sso_admin.create_instance(Name="sim2real-behav-idc")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ConflictException",):
                raise
    deadline = time.time() + 180
    while time.time() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        time.sleep(3)
    raise AssertionError(
        "no IAM Identity Center instance could be enabled in this account/region"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListUsers to reject Extensions=['not:a:real:extension'], but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

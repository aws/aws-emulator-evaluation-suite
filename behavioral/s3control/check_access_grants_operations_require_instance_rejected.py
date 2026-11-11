"""access-grants-operations-require-instance-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-grants-operations-require-instance-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:s3-access-grants-instance")
def run(ctx) -> None:
    """Access Grants reads fail with AccessGrantsInstanceNotExistsError (Dissociate: InvalidRequest)
    until the instance exists, then all answer; a second CreateAccessGrantsInstance is refused with
    AccessGrantsInstanceAlreadyExists and the original instance stays intact.
    """
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # The instance is a per-account singleton, so the check needs an account that has none.
    try:
        s3c.get_access_grants_instance(AccountId=account)
        raise CheckPreconditionInstanceExists()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AccessGrantsInstanceNotExistsError":
            raise

    # With no instance, the read surface reports the specific not-exists code.
    reads = {
        "GetAccessGrantsInstance":
            lambda: s3c.get_access_grants_instance(AccountId=account),
        "ListAccessGrants": lambda: s3c.list_access_grants(AccountId=account),
        "ListAccessGrantsLocations":
            lambda: s3c.list_access_grants_locations(AccountId=account),
        "ListCallerAccessGrants": lambda: s3c.list_caller_access_grants(AccountId=account),
    }
    for operation, call in reads.items():
        code, code_msg = _error(call)
        assert code == "AccessGrantsInstanceNotExistsError", (
            f"{operation} with no instance returned {code!r}, "
            "expected AccessGrantsInstanceNotExistsError"
        )
        code_want = "Access Grants Instance does not exist"
        assert code_msg == code_want, (
            f"the refusal carried message {code_msg!r}, expected {code_want!r}"
        )
    dissoc, dissoc_msg = _error(
        lambda: s3c.dissociate_access_grants_identity_center(AccountId=account)
    )
    assert dissoc == "InvalidRequest", (
        f"DissociateAccessGrantsIdentityCenter with no instance returned {dissoc!r}, "
        "expected InvalidRequest"
    )
    dissoc_want = "The specified Access Grants Instance does not exist"
    assert dissoc_msg == dissoc_want, (
        f"the refusal carried message {dissoc_msg!r}, expected {dissoc_want!r}"
    )

    # Positive control: creating the instance flips ALL FOUR reads to answering, not just the
    # ones easiest to check.
    s3c.create_access_grants_instance(
        AccountId=account, Tags=[{"Key": "sim2real", "Value": "agreq"}]
    )
    ctx.on_cleanup(lambda: _drop_instance(s3c, account))
    instance = s3c.get_access_grants_instance(AccountId=account)
    assert instance["AccessGrantsInstanceId"] == "default", (
        f"GetAccessGrantsInstance reported id {instance.get('AccessGrantsInstanceId')!r}, "
        "expected 'default'"
    )
    assert s3c.list_access_grants(AccountId=account).get("AccessGrantsList", []) == [], (
        "ListAccessGrants on a fresh instance did not return an empty grant list"
    )
    assert (
        s3c.list_access_grants_locations(AccountId=account).get("AccessGrantsLocationsList", [])
        == []
    ), "ListAccessGrantsLocations on a fresh instance did not return an empty locations list"
    assert (
        s3c.list_caller_access_grants(AccountId=account).get("CallerAccessGrantsList", []) == []
    ), "ListCallerAccessGrants on a fresh instance did not return an empty grants list"

    # The instance is a singleton: a second create is refused, and — the terminal, independent
    # read — the original instance is still intact rather than clobbered by the rejected call.
    dup, dup_msg = _error(lambda: s3c.create_access_grants_instance(AccountId=account))
    assert dup == "AccessGrantsInstanceAlreadyExists", (
        f"a second CreateAccessGrantsInstance returned {dup!r}, "
        "expected AccessGrantsInstanceAlreadyExists"
    )
    dup_want = "Access Grants Instance already exists"
    assert dup_msg == dup_want, (
        f"the refusal carried message {dup_msg!r}, expected {dup_want!r}"
    )
    survivor = s3c.get_access_grants_instance(AccountId=account)
    assert survivor["AccessGrantsInstanceId"] == "default", (
        "the rejected duplicate CreateAccessGrantsInstance left the original instance as "
        f"{survivor.get('AccessGrantsInstanceId')!r}, expected it untouched at 'default'"
    )



class CheckPreconditionInstanceExists(AssertionError):
    """Raised when the account already has an Access Grants instance (an environment condition)."""

    def __init__(self) -> None:
        super().__init__(
            "an Access Grants instance already exists in this account; this check requires "
            "the no-instance state and cannot run — report as an environment condition"
        )


def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _drop_instance(s3c, account: str) -> None:
    try:
        s3c.delete_access_grants_instance(AccountId=account)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AccessGrantsInstanceNotExistsError":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

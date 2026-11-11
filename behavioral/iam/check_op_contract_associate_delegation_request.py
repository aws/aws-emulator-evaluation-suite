"""op-contract-associateDelegationRequest."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-associateDelegationRequest"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateDelegationRequest with a well-formed unknown DelegationRequestId fails with
    NoSuchEntity and its exact message, and GetDelegationRequest for that id fails the same
    way; ListDelegationRequests succeeds first."""
    iam = ctx.client("iam")
    fake_id = ctx.unique_name("sim2realdeleg")

    # Positive control: the delegation-request read surface must work before a NoSuchEntity
    # on the write/read calls below can be trusted as "this specific id doesn't exist" rather
    # than a blanket denial that happens to share the same error code.
    listed = iam.list_delegation_requests()
    assert "DelegationRequests" in listed, (
        f"expected ListDelegationRequests to return a DelegationRequests list as a "
        f"precondition control, got keys {sorted(listed.keys())}"
    )

    # IAM is a query-protocol service: the wire-level Error.Code omits the "Exception"
    # suffix that appears in the operation's documented exception shape name (e.g. the
    # shape "NoSuchEntityException" is returned on the wire as Code "NoSuchEntity").
    code, message = _error(lambda: iam.associate_delegation_request(DelegationRequestId=fake_id))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"Delegation request not found: {fake_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    read_code, read_message = _error(lambda: iam.get_delegation_request(DelegationRequestId=fake_id))
    assert read_code == "NoSuchEntity", (
        f"expected the same id to still be unresolvable via GetDelegationRequest, got {read_code}"
    )
    expected = f"DelegationRequest not found: {fake_id}"
    assert read_message == expected, f"expected message {expected!r}, got {read_message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

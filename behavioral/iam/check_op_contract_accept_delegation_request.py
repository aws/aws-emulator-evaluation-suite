"""op-contract-acceptDelegationRequest."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-acceptDelegationRequest"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptDelegationRequest rejects a well-formed but unknown DelegationRequestId with
    NoSuchEntityException, and the same id remains unresolvable via GetDelegationRequest
    (proving no delegation request was fabricated as a side effect of the accept call)."""
    iam = ctx.client("iam")
    fake_id = ctx.unique_name("sim2realdeleg")

    # IAM is a query-protocol service: the wire-level Error.Code omits the "Exception"
    # suffix that appears in the operation's documented exception shape name (e.g. the
    # shape "NoSuchEntityException" is returned on the wire as Code "NoSuchEntity").
    code, message = _error(lambda: iam.accept_delegation_request(DelegationRequestId=fake_id))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"DelegationRequest not found: {fake_id}"
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
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

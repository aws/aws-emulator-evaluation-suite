"""start-access-request-denied-without-permission-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-access-request-denied-without-permission-boundary"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With just-in-time node access not enabled, StartAccessRequest fails with ValidationException
    "Just-In-Time Node Access service is not enabled in this account." while ListDocuments answers."""
    ssm = ctx.client("ssm")

    # positive control: the client can reach the SSM API and issue ordinary calls fine,
    # so the rejection below is not just a broken client/endpoint
    control = ssm.list_documents(MaxResults=5)
    assert "DocumentIdentifiers" in control, f"ListDocuments positive control missing key: {control!r}"

    # break exactly one thing: request just-in-time access to a node with no approval
    # policy / grant configured for this caller (the default state of a fresh account)
    code, message = _error_code_and_message(
        lambda: ssm.start_access_request(
            Reason="sim2real behavioral fidelity check - no grant is configured for this caller",
            Targets=[{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    assert message == "Just-In-Time Node Access service is not enabled in this account.", (
        f"expected the Just-In-Time Node Access feature-gate message, got {message!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection but call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

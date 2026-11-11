"""list-tags-for-resource-well-formed-arn-access-denied-vs-malformed-validation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-well-formed-arn-access-denied-vs-malformed-validation"
GROUP = "error-semantics"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource refuses a well-formed PMA ARN in another account with AccessDeniedException
    and its exact resource-policy message, and rejects a string that is not a taggable ARN with
    ValidationException (exact message and fieldList)."""
    client = ctx.client("partnercentral-channel")

    control = client.list_channel_handshakes(
        handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
        catalog=CATALOG,
        participantType="SENDER",
        maxResults=10,
    )
    assert isinstance(control.get("items"), list), (
        f"expected ListChannelHandshakes to succeed for a healthy caller, got {control}"
    )

    fake_arn = (
        f"arn:aws:partnercentral:us-east-1:111111111111:catalog/{CATALOG}"
        "/program-management-account/pma-1111111111111"
    )

    def _attempt_well_formed():
        client.list_tags_for_resource(resourceArn=fake_arn)

    denied = _error(_attempt_well_formed)
    code1 = denied["Error"]["Code"]
    assert code1 == "AccessDeniedException", f"expected AccessDeniedException, got {code1}"
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    assert denied["Error"].get("Message") == (
        f"User: {caller_arn} is not authorized to perform: partnercentral:ListTagsForResource "
        f"on resource: {fake_arn} because no resource-based policy allows the "
        "partnercentral:ListTagsForResource action"
    ), denied

    def _attempt_malformed():
        client.list_tags_for_resource(resourceArn="not-an-arn-at-all")

    malformed = _error(_attempt_malformed)
    code2 = malformed["Error"]["Code"]
    assert code2 == "ValidationException", f"expected ValidationException, got {code2}"
    assert malformed["Error"].get("Message") == "1 validation error detected.", malformed
    assert malformed.get("fieldList") == [
        {
            "name": "resourceArn",
            "code": "INVALID_STRING_FORMAT",
            "message": "Value at 'resourceArn' failed to satisfy constraint: Member must "
            "satisfy regular expression pattern: a full resource ARN",
        }
    ], (
        f"fieldList={malformed.get('fieldList')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore response dict (Code/Message under "Error", modeled
    error members such as fieldList at the top level). An unexpected SUCCESS raises, so a
    target that accepts input real AWS refuses cannot pass as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

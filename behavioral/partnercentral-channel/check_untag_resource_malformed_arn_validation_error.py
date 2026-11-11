"""untag-resource-malformed-arn-validation-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-malformed-arn-validation-error"
GROUP = "error-semantics"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource rejects a resourceArn that is not a taggable-resource ARN with ValidationException
    (exact message and fieldList), while a well-formed PMA ARN in another account gets
    AccessDeniedException with its exact resource-policy message."""
    client = ctx.client("partnercentral-channel")
    fake_arn = (
        f"arn:aws:partnercentral:us-east-1:111111111111:catalog/{CATALOG}"
        "/relationship/rs-1111111111111"
    )

    def _attempt():
        client.untag_resource(resourceArn=fake_arn, tagKeys=["sim2real-x"])

    malformed = _error(_attempt)
    code = malformed["Error"]["Code"]
    assert code == "ValidationException", f"expected ValidationException, got {code}"
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

    well_formed_arn = (
        f"arn:aws:partnercentral:us-east-1:111111111111:catalog/{CATALOG}"
        "/program-management-account/pma-1111111111111"
    )

    def _attempt_well_formed():
        client.untag_resource(resourceArn=well_formed_arn, tagKeys=["sim2real-x"])

    denied = _error(_attempt_well_formed)
    code2 = denied["Error"]["Code"]
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}"
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    assert denied["Error"].get("Message") == (
        f"User: {caller_arn} is not authorized to perform: partnercentral:UntagResource "
        f"on resource: {well_formed_arn} because no resource-based policy allows the "
        "partnercentral:UntagResource action"
    ), denied


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

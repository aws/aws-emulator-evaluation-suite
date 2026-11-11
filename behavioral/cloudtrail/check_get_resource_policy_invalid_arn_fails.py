"""get-resource-policy-invalid-arn-fails."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-resource-policy-invalid-arn-fails"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy answers ValidationException with the resourceArn pattern message for a malformed ARN,
    and ResourceNotFoundException "The channel <ARN> was not found." for a well-formed unknown channel ARN."""
    cloudtrail = ctx.client("cloudtrail")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    malformed_arn = "not-an-arn at all!!"
    code, message = _error(lambda: cloudtrail.get_resource_policy(ResourceArn=malformed_arn))
    assert code == "ValidationException", f"unexpected error code: {code}"
    assert message == (
        "1 validation error detected: Value at 'resourceArn' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^[a-zA-Z0-9._/\\-:]+$"
    ), message

    # a syntactically well-formed CloudTrail channel ARN that does not exist is a
    # different failure mode, discriminating malformed-ARN from resource-not-found
    well_formed_missing_arn = (
        f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    )
    code2, message2 = _error(
        lambda: cloudtrail.get_resource_policy(ResourceArn=well_formed_missing_arn)
    )
    assert code2 != "ValidationException", f"unexpected error code: {code2}"
    assert code2 == "ResourceNotFoundException", f"unexpected error code: {code2}"
    assert message2 == f"The channel {well_formed_missing_arn} was not found.", message2


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

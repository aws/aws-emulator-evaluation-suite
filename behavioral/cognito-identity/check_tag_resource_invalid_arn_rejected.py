"""tag-resource-invalid-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]

_MALFORMED_ARN_MESSAGE = "ARN in SecureServiceAuthStrategy failed validation:"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on a malformed identity pool ARN are refused with
    InvalidParameterException and the exact message, while TagResource on a real pool's ARN stores a
    tag ListTagsForResource returns."""
    ci = ctx.client("cognito-identity")

    # Positive control: TagResource against a real, well-formed ARN succeeds and persists.
    pool_name = ctx.unique_name("sim2real-idp-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    valid_arn = f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"

    ci.tag_resource(ResourceArn=valid_arn, Tags={"k": "v"})
    listed = ci.list_tags_for_resource(ResourceArn=valid_arn)["Tags"]
    assert listed.get("k") == "v", f"positive control: expected tag to persist, got {listed!r}"

    # Break exactly one thing: swap the well-formed ARN for a malformed one.
    malformed_arn = "this-is-definitely-not-an-arn-1234567890"
    code, message = _error(lambda: ci.tag_resource(ResourceArn=malformed_arn, Tags={"k": "v"}))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for malformed ARN, got {code!r}"
    )
    assert message == _MALFORMED_ARN_MESSAGE, message

    # Effect absent: no dangling tag entry is readable under the malformed identifier either.
    list_code, list_message = _error(lambda: ci.list_tags_for_resource(ResourceArn=malformed_arn))
    assert list_code == "InvalidParameterException", (
        f"expected reading tags for the same malformed ARN to also fail, got {list_code!r}"
    )
    assert list_message == _MALFORMED_ARN_MESSAGE, list_message


def _error(fn):
    """Call fn(); return its botocore Error (Code, Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

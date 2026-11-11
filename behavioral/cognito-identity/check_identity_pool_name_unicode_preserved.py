"""identity-pool-name-unicode-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "identity-pool-name-unicode-preserved"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value using every allowed special character round-trips byte-identical through
    CreateIdentityPool and DescribeIdentityPool, and an emoji tag value is refused with
    InvalidParameterException and the exact allowed-characters message."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-pool-")
    tag_value = "a_b.c:d/e=f+g-h@i j"  # every allowed special character, plus a space

    resp = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=False,
        IdentityPoolTags={"SpecialCharsTag": tag_value},
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    assert resp["IdentityPoolTags"].get("SpecialCharsTag") == tag_value, (
        "CreateIdentityPool did not echo the special-character tag value byte-identically: "
        f"{resp.get('IdentityPoolTags')!r}"
    )

    described = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolTags"].get("SpecialCharsTag") == tag_value, (
        "DescribeIdentityPool did not preserve the special-character tag value byte-identically: "
        f"{described.get('IdentityPoolTags')!r}"
    )
    assert described["IdentityPoolName"] == name, (
        f"DescribeIdentityPool returned a different name: {described.get('IdentityPoolName')!r} "
        f"!= {name!r}"
    )

    # Negative: an emoji tag value is always invalid. Unicode letters (accented Latin, CJK) are
    # accepted as tag values, so the negative uses a symbol codepoint, not merely a non-ASCII one.
    rejected_name = ctx.unique_name("sim2real-behav-pool-reject-")
    code, message = _invalid_tag_error(ci, rejected_name)
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for an emoji tag value, got {code!r}: {message!r}"
    )
    expected = (
        "Tags can only contain letters, numbers, spaces, and the following special "
        "characters: _ . : / = + - @"
    )
    assert message == expected, (
        f"expected InvalidParameterException message {expected!r} for an emoji tag value, "
        f"got {message!r}"
    )


def _invalid_tag_error(ci, name: str) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        resp = ci.create_identity_pool(
            IdentityPoolName=name,
            AllowUnauthenticatedIdentities=False,
            IdentityPoolTags={"UnicodeTag": "\U0001f600"},
        )
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    else:
        # Unexpectedly succeeded -- clean up immediately so we don't leak.
        ci.delete_identity_pool(IdentityPoolId=resp["IdentityPoolId"])
        raise AssertionError(
            f"CreateIdentityPool unexpectedly accepted an emoji tag value for pool {name!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

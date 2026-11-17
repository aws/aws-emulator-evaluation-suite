"""tag-user-reserved-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-user-reserved-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects a tag key with the 'aws:' prefix, but it succeeded: {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagUser rejects a tag key using the AWS-reserved 'aws:' prefix with InvalidInput,
    applies no tag, while a normal tag key on the same user succeeds."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-tur-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    bad_tags = [{"Key": "aws:sim2real-marker", "Value": "should-not-apply"}]
    code, message = _error(lambda: iam.tag_user(UserName=user_name, Tags=bad_tags))
    assert code == "InvalidInput", f"expected InvalidInput, got {code!r}"
    expected = "Tag keys beginning with aws: are reserved for system use."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_reject = iam.list_user_tags(UserName=user_name)["Tags"]
    assert after_reject == [], f"expected no tags applied after a rejected TagUser, got {after_reject!r}"

    good_tags = [{"Key": "team", "Value": "payments"}]
    iam.tag_user(UserName=user_name, Tags=good_tags)
    listed = iam.list_user_tags(UserName=user_name)["Tags"]
    assert {(t["Key"], t["Value"]) for t in listed} == {(t["Key"], t["Value"]) for t in good_tags}, (
        f"expected tag {good_tags!r} to apply, got {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

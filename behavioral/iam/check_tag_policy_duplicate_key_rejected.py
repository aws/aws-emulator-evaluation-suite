"""tag-policy-duplicate-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-policy-duplicate-key-rejected"
GROUP = "tagging"
SERVICES = ["iam"]

_POLICY_DOC = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}'
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagPolicy rejects a call that supplies the exact same tag key twice and never partially
    applies it; two keys differing only by case are distinct tags and both are stored.
    """
    iam = ctx.client("iam")
    policy_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-tpd-"),
        PolicyDocument=_POLICY_DOC,
        Tags=[{"Key": "Team", "Value": "payments"}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    def _tags():
        return {t["Key"]: t["Value"] for t in iam.list_policy_tags(PolicyArn=policy_arn)["Tags"]}

    assert _tags() == {"Team": "payments"}, f"unexpected initial tags {_tags()!r}"

    code, message = _error(
        lambda: iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[{"Key": "Team", "Value": "a"}, {"Key": "Team", "Value": "b"}],
        )
    )
    assert code == "InvalidInput", f"expected InvalidInput for an exact duplicate key, got {code!r}: {message!r}"
    expected = "Duplicate tag keys found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert _tags() == {"Team": "payments"}, "a rejected TagPolicy call must not mutate existing tags"

    iam.tag_policy(
        PolicyArn=policy_arn,
        Tags=[{"Key": "Region", "Value": "x"}, {"Key": "region", "Value": "y"}],
    )
    assert _tags() == {"Team": "payments", "Region": "x", "region": "y"}, (
        f"keys differing only by case must be stored as distinct tags, got {_tags()!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

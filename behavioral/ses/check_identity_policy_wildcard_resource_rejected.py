"""identity-policy-wildcard-resource-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-wildcard-resource-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy rejects a bare "*" Resource with InvalidPolicy and does not store it, while
    an otherwise-identical policy naming the identity's own ARN is accepted."""
    ses = ctx.client("ses")
    email = _unique_email(ctx, "policy-star-")
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    account = ctx.client("sts").get_caller_identity()["Account"]
    identity_arn = f"arn:aws:ses:{ctx.region}:{account}:identity/{email}"

    # Positive control: an otherwise-identical policy naming a real ARN is accepted.
    control_policy = (
        '{"Version":"2008-10-17","Statement":[{"Sid":"control","Effect":"Allow",'
        '"Principal":{"AWS":"*"},"Action":"ses:SendEmail","Resource":"'
        + identity_arn
        + '"}]}'
    )
    ses.put_identity_policy(
        Identity=email, PolicyName="control-policy", Policy=control_policy
    )
    assert "control-policy" in ses.list_identity_policies(Identity=email)["PolicyNames"], (
        "positive control: a policy naming a real ARN Resource was not stored"
    )

    # SES is stricter than generic IAM here: Resource must be an ARN, so a bare "*" is refused.
    star_policy = (
        '{"Version":"2008-10-17","Statement":[{"Sid":"star","Effect":"Allow",'
        '"Principal":{"AWS":"*"},"Action":"ses:SendEmail","Resource":"*"}]}'
    )
    err, msg = _err(
        lambda: ses.put_identity_policy(
            Identity=email, PolicyName="star-policy", Policy=star_policy
        )
    )
    assert err == "InvalidPolicy", (
        f"expected InvalidPolicy for a wildcard Resource, got {err!r}: {msg!r}"
    )
    expected_msg = "Invalid ARN: ARNs must start with 'arn:': *"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    names = ses.list_identity_policies(Identity=email)["PolicyNames"]
    assert "star-policy" not in names, "rejected wildcard policy was still stored"
    assert "control-policy" in names, (
        "positive control policy vanished after the rejected wildcard call"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

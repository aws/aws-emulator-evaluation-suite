"""put-identity-policy-malformed-json-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-identity-policy-malformed-json-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy rejects a malformed policy document with InvalidPolicy and never stores it,
    while a well-formed policy on the same identity is accepted, so the refusal is specific."""
    ses = ctx.client("ses")
    email = _unique_email(ctx)
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    err, msg = _err(
        lambda: ses.put_identity_policy(
            Identity=email,
            PolicyName=ctx.unique_name("sim2real-behav-badpolicy-"),
            Policy="{ this is not valid json",
        )
    )
    assert err == "InvalidPolicy", (
        f"expected InvalidPolicy for a malformed policy document, got {err!r}: {msg!r}"
    )
    assert msg == "Unable to parse policy.", f"expected message 'Unable to parse policy.', got {msg!r}"

    names = ses.list_identity_policies(Identity=email)["PolicyNames"]
    assert names == [], f"a rejected policy was still persisted: {names}"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    good_policy_name = ctx.unique_name("sim2real-behav-goodpolicy-")
    good_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:aws:iam::{account_id}:root"}},'
        '"Action":"ses:SendEmail",'
        f'"Resource":"arn:aws:ses:{ctx.region}:{account_id}:identity/{email}"}}]}}'
    )
    ses.put_identity_policy(Identity=email, PolicyName=good_policy_name, Policy=good_policy)
    ctx.on_cleanup(
        lambda _n=email, _p=good_policy_name: ses.delete_identity_policy(Identity=_n, PolicyName=_p)
    )

    names_after = ses.list_identity_policies(Identity=email)["PolicyNames"]
    assert good_policy_name in names_after, (
        f"positive-control policy was not attached: {names_after}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""identity-policy-refused-by-both-apis-for-an-identity-never-created."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-refused-by-both-apis-for-an-identity-never-created"
GROUP = "shared-state-v1-v2"
SERVICES = ["ses", "sesv2"]

_V1_UNKNOWN_IDENTITY = ("InvalidParameterValue", "Invalid identity. Must be a verified email address or domain.")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The (Error.Code, Error.Message) ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _identity_policy(ctx, identity: str, sid: str) -> str:
    return json.dumps(
        {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                    "Action": "ses:SendEmail",
                    "Resource": f"arn:aws:ses:{ctx.region}:{ctx.account}:identity/{identity}",
                }
            ],
        }
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy and CreateEmailIdentityPolicy each refuse, with their own exact
    error, a policy naming an identity that was never created, and neither stores it; the
    same shape of policy on a real identity is accepted through both APIs.
    """
    v1 = ctx.client("ses")
    v2 = ctx.client("sesv2")

    ghost = f"{ctx.unique_name('sim2real-behav-idpol-ghost-')}@example.com"
    ghost_pol = ctx.unique_name("sim2real-behav-idpol-ghost-pol-")
    ghost_doc = _identity_policy(ctx, ghost, "ghost")
    v2_missing = ("NotFoundException", f"Email identity <{ghost}> does not exist.")

    v1_err = _error(lambda: v1.put_identity_policy(Identity=ghost, PolicyName=ghost_pol, Policy=ghost_doc))
    assert v1_err == _V1_UNKNOWN_IDENTITY, f"expected {_V1_UNKNOWN_IDENTITY!r}, got {v1_err!r}"

    v2_err = _error(
        lambda: v2.create_email_identity_policy(EmailIdentity=ghost, PolicyName=ghost_pol, Policy=ghost_doc)
    )
    assert v2_err == v2_missing, f"expected {v2_missing!r}, got {v2_err!r}"

    # Effect absent: neither rejected call implicitly registered the identity or stored a policy.
    names = v1.list_identity_policies(Identity=ghost)["PolicyNames"]
    assert names == [], f"expected v1 ListIdentityPolicies to list no policy for {ghost!r}, got {names!r}"

    get_err = _error(lambda: v2.get_email_identity_policies(EmailIdentity=ghost))
    assert get_err == v2_missing, f"expected {v2_missing!r}, got {get_err!r}"

    # Positive control: the identical shape of policy, on a real identity, is accepted by both.
    identity = f"{ctx.unique_name('sim2real-behav-idpol-real-')}@example.com"
    v1.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: v1.delete_identity(Identity=identity))

    real_pol = ctx.unique_name("sim2real-behav-idpol-real-pol-")
    real_doc = _identity_policy(ctx, identity, "real")
    v1.put_identity_policy(Identity=identity, PolicyName=real_pol, Policy=real_doc)
    ctx.on_cleanup(_teardown(lambda: v1.delete_identity_policy(Identity=identity, PolicyName=real_pol)))

    names_real = v1.list_identity_policies(Identity=identity)["PolicyNames"]
    assert names_real == [real_pol], (
        f"positive control failed: expected v1 ListIdentityPolicies to list exactly [{real_pol!r}] "
        f"for a real identity, got {names_real!r}"
    )
    v2_policies = v2.get_email_identity_policies(EmailIdentity=identity)["Policies"]
    assert set(v2_policies) == {real_pol}, (
        f"positive control failed: expected v2 Policies keys {{{real_pol!r}}}, got {set(v2_policies)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

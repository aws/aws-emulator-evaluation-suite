"""identity-policy-rejects-an-unparseable-document."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-rejects-an-unparseable-document"
GROUP = "identity-policies"
SERVICES = ["ses"]

def _error(fn, what: str) -> tuple[str, str]:
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} SUCCEEDED; real AWS rejects it")


def _ignore_missing(fn) -> None:
    fn()


def _policy_names(ses, identity: str) -> set[str]:
    """Every policy name on an identity, following NextToken."""
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = ses.list_identity_policies(Identity=identity, **kwargs)
        names.update(page.get("PolicyNames", []))
        token = page.get("NextToken")
        if not token:
            return names


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy with unparseable JSON fails with InvalidPolicy and stores nothing; a valid
    document under the same name round-trips, and a later unparseable overwrite leaves it unchanged.
    """
    ses = ctx.client("ses")
    account = ctx.client("sts").get_caller_identity()["Account"]
    domain = ctx.unique_name("sim2real-behav-ses-") + ".example.com"
    policy_name = "sim2real-behav-authz"

    ses.verify_domain_identity(Domain=domain)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: ses.delete_identity(Identity=domain)))
    assert _policy_names(ses, domain) == set(), (
        f"a freshly created identity {domain!r} already carries policies "
        f"{_policy_names(ses, domain)!r}"
    )

    code, message = _error(
        lambda: ses.put_identity_policy(
            Identity=domain, PolicyName=policy_name, Policy='{"Version": "2012-10-17"'
        ),
        "PutIdentityPolicy with truncated JSON",
    )
    assert code == "InvalidPolicy", f"expected InvalidPolicy, got {code!r}: {message!r}"
    assert message == "Unable to parse policy.", (
        f"expected 'Unable to parse policy.', got {message!r}"
    )

    # Effect absent: nothing was stored under the name the refused call used.
    assert _policy_names(ses, domain) == set(), (
        f"{policy_name!r} (or something) was stored on {domain!r} despite the refusal: "
        f"{_policy_names(ses, domain)!r}"
    )

    # Same identity and policy name: only the document was wrong.
    document = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "sim2realAllowSend",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": ["ses:SendEmail", "ses:SendRawEmail"],
            "Resource": f"arn:aws:ses:{ctx.region}:{account}:identity/{domain}",
        }],
    }
    ses.put_identity_policy(
        Identity=domain, PolicyName=policy_name, Policy=json.dumps(document)
    )
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: ses.delete_identity_policy(Identity=domain, PolicyName=policy_name)
    ))
    assert _policy_names(ses, domain) == {policy_name}, (
        f"after the valid put, policies are {_policy_names(ses, domain)!r}, expected "
        f"{{{policy_name!r}}}"
    )
    stored = ses.get_identity_policies(Identity=domain, PolicyNames=[policy_name])["Policies"]
    assert set(stored) == {policy_name}, (
        f"GetIdentityPolicies returned {sorted(stored)!r}, expected [{policy_name!r}]"
    )
    round_tripped = json.loads(stored[policy_name])
    assert round_tripped["Statement"][0]["Action"] == document["Statement"][0]["Action"], (
        f"stored Action is {round_tripped['Statement'][0]['Action']!r}, expected "
        f"{document['Statement'][0]['Action']!r}"
    )
    assert round_tripped["Statement"][0]["Resource"] == document["Statement"][0]["Resource"], (
        f"stored Resource is {round_tripped['Statement'][0]['Resource']!r}, expected "
        f"{document['Statement'][0]['Resource']!r}"
    )

    # And a refusal after a successful put must not disturb what is already stored.
    code, message = _error(
        lambda: ses.put_identity_policy(
            Identity=domain, PolicyName=policy_name, Policy="not json at all"
        ),
        "PutIdentityPolicy overwriting a valid policy with garbage",
    )
    assert code == "InvalidPolicy", (
        f"expected InvalidPolicy on the overwrite attempt, got {code!r}: {message!r}"
    )
    after = ses.get_identity_policies(Identity=domain, PolicyNames=[policy_name])["Policies"]
    assert json.loads(after[policy_name]) == round_tripped, (
        f"the refused overwrite changed the stored policy to {after[policy_name]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""identity-policy-overwrite-preserves-exact-document-and-single-listing."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-overwrite-preserves-exact-document-and-single-listing"
GROUP = "error-semantics"
SERVICES = ["ses"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _stored(ses, identity, policy_name):
    policies = ses.get_identity_policies(Identity=identity, PolicyNames=[policy_name])["Policies"]
    return json.loads(policies[policy_name])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy overwriting a stored policy with a wildcard-Resource document is
    refused, leaving the stored document unchanged as parsed JSON; a following overwrite with a
    valid identity-ARN document replaces it exactly, and the name is listed once throughout."""
    ses = ctx.client("ses")
    account = ctx.account
    identity = ctx.unique_name("sim2real-behav-idpolex-") + "@example.com"
    ses.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=identity))

    identity_arn = f"arn:aws:ses:{ctx.region}:{account}:identity/{identity}"
    principal_arn = f"arn:aws:iam::{account}:root"
    policy_name = ctx.unique_name("sim2real-behav-policy-")

    original_doc = {
        "Version": "2008-10-17",
        "Statement": [{
            "Sid": "original",
            "Effect": "Allow",
            "Principal": {"AWS": principal_arn},
            "Action": "ses:SendEmail",
            "Resource": identity_arn,
        }],
    }
    ses.put_identity_policy(
        Identity=identity, PolicyName=policy_name, Policy=json.dumps(original_doc)
    )
    ctx.on_cleanup(lambda: ses.delete_identity_policy(Identity=identity, PolicyName=policy_name))

    names_after_create = ses.list_identity_policies(Identity=identity)["PolicyNames"]
    assert names_after_create.count(policy_name) == 1, (
        f"expected {policy_name!r} listed exactly once after the first put, got {names_after_create!r}"
    )

    wildcard_doc = {
        "Version": "2008-10-17",
        "Statement": [{
            "Sid": "wildcard",
            "Effect": "Allow",
            "Principal": {"AWS": principal_arn},
            "Action": "ses:SendEmail",
            "Resource": "*",
        }],
    }
    _INVALID_POLICY = ("InvalidPolicy", "Invalid ARN: ARNs must start with 'arn:': *")
    code, message = _error(
        lambda: ses.put_identity_policy(
            Identity=identity, PolicyName=policy_name, Policy=json.dumps(wildcard_doc)
        )
    )
    assert (code, message) == _INVALID_POLICY, (
        f"expected {_INVALID_POLICY!r} overwriting with a wildcard Resource, got {(code, message)!r}"
    )

    stored_after_reject = _stored(ses, identity, policy_name)
    assert stored_after_reject == original_doc, (
        f"the refused overwrite changed the stored document: expected the untouched original "
        f"{original_doc!r}, got {stored_after_reject!r}"
    )
    names_after_reject = ses.list_identity_policies(Identity=identity)["PolicyNames"]
    assert names_after_reject.count(policy_name) == 1, (
        f"expected {policy_name!r} still listed exactly once after the refused overwrite, "
        f"got {names_after_reject!r}"
    )

    replacement_doc = {
        "Version": "2008-10-17",
        "Statement": [{
            "Sid": "replacement",
            "Effect": "Allow",
            "Principal": {"AWS": principal_arn},
            "Action": "ses:SendEmail",
            "Resource": identity_arn,
        }],
    }
    ses.put_identity_policy(
        Identity=identity, PolicyName=policy_name, Policy=json.dumps(replacement_doc)
    )

    stored_after_accept = _stored(ses, identity, policy_name)
    assert stored_after_accept == replacement_doc, (
        f"expected the accepted overwrite to store exactly {replacement_doc!r}, "
        f"got {stored_after_accept!r}"
    )
    names_after_accept = ses.list_identity_policies(Identity=identity)["PolicyNames"]
    assert names_after_accept.count(policy_name) == 1, (
        f"expected {policy_name!r} listed exactly once after the accepted overwrite, "
        f"got {names_after_accept!r} (the earlier refusal must not have left a duplicate entry)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

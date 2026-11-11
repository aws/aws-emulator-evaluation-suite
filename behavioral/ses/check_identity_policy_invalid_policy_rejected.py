"""identity-policy-invalid-policy-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "identity-policy-invalid-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy with a non-JSON Policy is rejected with InvalidPolicy and leaves the
    existing policy unchanged; a valid update to the same policy name is still accepted."""
    ses = ctx.client("ses")
    identity = f"{ctx.unique_name('sim2real-ses-id')}@example.com"
    ses.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=identity))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_name = ctx.unique_name("sim2real-ses-pol-")
    valid_policy = {
        "Version": "2008-10-17",
        "Statement": [
            {
                "Sid": "AllowDelegateSend",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ses:SendEmail",
                "Resource": f"arn:aws:ses:{ctx.region}:{account_id}:identity/{identity}",
            }
        ],
    }
    ses.put_identity_policy(
        Identity=identity, PolicyName=policy_name, Policy=json.dumps(valid_policy)
    )

    stored = json.loads(
        ses.get_identity_policies(Identity=identity, PolicyNames=[policy_name])[
            "Policies"
        ][policy_name]
    )
    assert stored["Statement"][0]["Sid"] == "AllowDelegateSend", (
        f"expected the just-stored policy to round-trip with Sid AllowDelegateSend, got {stored!r}"
    )

    code, msg = _error_code(
        lambda: ses.put_identity_policy(
            Identity=identity, PolicyName=policy_name, Policy="this is not json"
        )
    )
    assert code == "InvalidPolicy", f"expected InvalidPolicy for a non-JSON Policy document, got {code!r}: {msg!r}"
    assert msg == "Unable to parse policy.", f"expected message 'Unable to parse policy.', got {msg!r}"

    # Effect absent: the previously-stored valid policy is unchanged by the rejected call.
    still_stored = json.loads(
        ses.get_identity_policies(Identity=identity, PolicyNames=[policy_name])[
            "Policies"
        ][policy_name]
    )
    assert still_stored == valid_policy, (
        f"rejected PutIdentityPolicy must leave the existing policy untouched; "
        f"expected {valid_policy!r}, got {still_stored!r}"
    )

    # Positive control: a syntactically valid update to the same policy name is accepted.
    valid_policy["Statement"][0]["Sid"] = "AllowDelegateSendV2"
    ses.put_identity_policy(
        Identity=identity, PolicyName=policy_name, Policy=json.dumps(valid_policy)
    )
    updated = json.loads(
        ses.get_identity_policies(Identity=identity, PolicyNames=[policy_name])[
            "Policies"
        ][policy_name]
    )
    assert updated["Statement"][0]["Sid"] == "AllowDelegateSendV2", (
        f"expected the follow-up valid update to be accepted with Sid AllowDelegateSendV2, got {updated!r}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore (Error code, Error message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected PutIdentityPolicy to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

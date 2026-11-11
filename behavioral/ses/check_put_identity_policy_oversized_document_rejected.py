"""put-identity-policy-oversized-document-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-identity-policy-oversized-document-rejected"
GROUP = "overly-permissive"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy rejects a valid-shaped policy over the 4000-byte limit with InvalidPolicy and
    never stores it, while a policy under the limit is accepted and round-trips."""
    ses = ctx.client("ses")
    identity = f"{ctx.unique_name('sim2real-ses-oversized-')}@example.com"
    ses.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=identity))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    principal_arn = f"arn:aws:iam::{account_id}:root"
    identity_arn = f"arn:aws:ses:{ctx.region}:{account_id}:identity/{identity}"

    def _policy_doc(sid_padding: str) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": sid_padding,
                        "Effect": "Allow",
                        "Principal": {"AWS": principal_arn},
                        "Action": "SES:SendEmail",
                        "Resource": identity_arn,
                    }
                ],
            }
        )

    # Padding chosen so the whole document comfortably clears the 4000-byte limit while
    # remaining syntactically valid JSON / IAM policy shape.
    oversized_doc = _policy_doc("A" * 4300)
    assert len(oversized_doc.encode("utf-8")) > 4000, "test document did not actually exceed 4000 bytes"

    oversized_policy_name = ctx.unique_name("sim2real-ses-oversized-policy-")
    code, msg = _error_code(
        lambda: ses.put_identity_policy(
            Identity=identity, PolicyName=oversized_policy_name, Policy=oversized_doc
        )
    )
    assert code == "InvalidPolicy", f"expected InvalidPolicy, got {code!r}: {msg!r}"
    # The trailing space is part of the message AWS returns.
    expected_msg = (
        f"The policy size, {len(oversized_doc)}, is larger than the max policy size, 4000. "
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    stored = ses.get_identity_policies(
        Identity=identity, PolicyNames=[oversized_policy_name]
    )["Policies"]
    assert oversized_policy_name not in stored, "oversized policy was stored despite rejection"

    small_policy_name = ctx.unique_name("sim2real-ses-smallpolicy-")
    small_doc = _policy_doc("sim2real-normal-sid")
    ses.put_identity_policy(Identity=identity, PolicyName=small_policy_name, Policy=small_doc)
    stored2 = ses.get_identity_policies(
        Identity=identity, PolicyNames=[small_policy_name]
    )["Policies"]
    assert json.loads(stored2[small_policy_name]) == json.loads(small_doc), (
        "positive-control policy did not round-trip"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected PutIdentityPolicy to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

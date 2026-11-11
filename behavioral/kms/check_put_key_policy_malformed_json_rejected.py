"""put-key-policy-malformed-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-key-policy-malformed-json-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutKeyPolicy with syntactically invalid JSON policy text is rejected with
    MalformedPolicyDocumentException, the stored policy is left unchanged, and a
    well-formed policy in the same request shape is accepted normally."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    original_policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]

    # Syntactically broken JSON (unterminated statement, no closing braces).
    malformed = '{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow" '
    code, message = _error(
        lambda: kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=malformed)
    )
    assert code == "MalformedPolicyDocumentException", (
        f"expected MalformedPolicyDocumentException, got {code}"
    )
    # AWS sends this refusal with no message text.
    assert message == "", f"expected an empty message, got {message!r}"

    # Effect absent: the key's policy was not overwritten by the rejected call.
    unchanged_policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    assert unchanged_policy == original_policy, (
        f"a rejected PutKeyPolicy must leave the stored document unchanged; "
        f"expected {original_policy!r}, got {unchanged_policy!r}"
    )

    # Positive control: a well-formed policy is accepted and persists.
    account_id = sts.get_caller_identity()["Account"]
    valid_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableRootPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=valid_policy)
    updated_policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    assert json.loads(updated_policy) == json.loads(valid_policy), (
        f"a well-formed policy in the same request shape must be accepted and persisted; "
        f"expected {valid_policy!r}, got {updated_policy!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

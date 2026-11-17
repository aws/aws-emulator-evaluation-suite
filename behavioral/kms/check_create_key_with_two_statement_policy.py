"""create-key-with-two-statement-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-key-with-two-statement-policy"
GROUP = "key_policy"
SERVICES = ["kms"]

_MALFORMED = ("MalformedPolicyDocumentException", "")


def _retry_on_access_denied(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Retry fn() past a just-created key's brief AccessDeniedException window; re-raise
    anything else immediately."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"call kept failing with AccessDeniedException: {last_exc}")


def expect_error(fn, code: str, message: str):
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises,
    because an implementation ACCEPTING a call real AWS refuses must not read as a message mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected code {code!r}, got {err.get('Code')!r}"
        assert err.get("Message", "") == message, (
            f"expected message {message!r}, got {err.get('Message', '')!r}"
        )
        return
    raise AssertionError(f"expected {code}, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateKey with a two-statement Policy stores both under "default" on an Enabled key,
    parsing equal to the submitted document. A Policy that is not JSON is refused with
    MalformedPolicyDocumentException; omitting Policy gets the exact default document."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    root_arn = f"arn:aws:iam::{account_id}:root"

    custom_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": root_arn},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowLogsServiceDecrypt",
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": "*",
            },
        ],
    }
    custom_key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-two-stmt-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
        Policy=json.dumps(custom_policy_doc),
    )["KeyMetadata"]
    custom_key_id = custom_key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=custom_key_id, PendingWindowInDays=7))

    assert custom_key["KeyState"] == "Enabled", (
        f"expected a newly created key to be Enabled, got {custom_key['KeyState']!r}"
    )

    policy_names = _retry_on_access_denied(
        lambda: kms.list_key_policies(KeyId=custom_key_id)
    )["PolicyNames"]
    assert policy_names == ["default"], f"expected only ['default'], got {policy_names!r}"

    custom_stored = json.loads(
        _retry_on_access_denied(
            lambda: kms.get_key_policy(KeyId=custom_key_id, PolicyName="default")
        )["Policy"]
    )
    assert custom_stored == custom_policy_doc, (
        f"expected the stored document to parse equal to the submitted one, "
        f"expected {custom_policy_doc!r}, got {custom_stored!r}"
    )

    # Negative: CreateKey with non-JSON Policy text is refused.
    expect_error(
        lambda: kms.create_key(
            Description=ctx.unique_name("sim2real-behav-kms-malformed-"),
            Policy="{ this is not valid JSON ",
        ),
        *_MALFORMED,
    )

    # Positive control: a key created with no Policy at all gets the exact default document.
    default_key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-default-policy-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    default_key_id = default_key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=default_key_id, PendingWindowInDays=7))

    default_stored = json.loads(
        _retry_on_access_denied(
            lambda: kms.get_key_policy(KeyId=default_key_id, PolicyName="default")
        )["Policy"]
    )
    expected_default_doc = {
        "Version": "2012-10-17",
        "Id": "key-default-1",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {"AWS": root_arn},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }
    assert default_stored == expected_default_doc, (
        f"expected the default document to be exactly {expected_default_doc!r}, "
        f"got {default_stored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

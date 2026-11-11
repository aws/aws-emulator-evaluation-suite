"""assume-role-packed-policy-too-large-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-packed-policy-too-large-rejected"
GROUP = "data-plane"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole with 50 maximal session tags fails PackedPolicyTooLarge with the documented message
    around the server-computed token size, while one small session tag succeeds with ASIA credentials
    and a PackedPolicySize under 100."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-packedpol-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # The inline `Policy` plaintext has its OWN hard 2048-character limit (enforced as a
    # plain ValidationError before the packed-size check ever runs), so oversizing the
    # Policy string doesn't reach PackedPolicyTooLarge. Session tags are the reliable way
    # to blow the *packed* (compressed-binary) size limit while staying under every raw
    # plaintext field limit: up to 50 tags, each with a 128-char key and a 256-char value
    # (all within their own individual limits), pack down to well over the combined quota.
    huge_tags = [
        {"Key": f"T{i:03d}" + ("k" * 124), "Value": "v" * 256} for i in range(50)
    ]
    small_tags = [{"Key": "Team", "Value": "engineering"}]

    def _attempt_oversized():
        return sts.assume_role(
            RoleArn=role_arn, RoleSessionName="oversized-tags-session", Tags=huge_tags
        )

    # Same trust-propagation window as the positive control below: the trust statement
    # (sts:AssumeRole + sts:TagSession for root) can take a few seconds to become
    # effective, during which even a request that SHOULD hit PackedPolicyTooLarge will
    # transiently see AccessDenied first. Poll past that window rather than treat the
    # very first attempt as authoritative.
    code, message = _wait_for_error_code(
        _attempt_oversized, expected_code="PackedPolicyTooLarge", transient_code="AccessDenied"
    )
    assert code == "PackedPolicyTooLarge", code
    # The token size is computed server-side from the whole session, so match around it.
    assert message.startswith("Serialized token too large for session. Token size of ") and message.endswith(
        " bytes exceeds the maximum allowed limit of 4096 bytes."
    ), message

    # Positive control: same role, same trust, a tiny session tag set -> succeeds and
    # issues usable credentials, proving the rejection above was about packed size, not
    # the role/trust or the Tags mechanism itself.
    control_resp = _wait_for_assume_role(
        sts,
        RoleArn=role_arn,
        RoleSessionName="small-tags-session",
        Tags=small_tags,
    )
    control_creds = control_resp["Credentials"]
    assert control_creds["AccessKeyId"].startswith("ASIA"), (
        f"expected an ASIA-prefixed temporary AccessKeyId, got {control_creds['AccessKeyId']!r}"
    )
    assert control_creds["SecretAccessKey"], "SecretAccessKey must be populated"
    assert control_creds["SessionToken"], "SessionToken must be populated"
    # Independent side-channel: AWS's own report of the packed size corroborates that the
    # control really is small, not just that the call happened not to error.
    assert control_resp["PackedPolicySize"] < 100, (
        f"the small-tags control's own reported PackedPolicySize was "
        f"{control_resp['PackedPolicySize']}, expected well under the 100% limit"
    )


def _wait_for_error_code(
    fn, expected_code: str, transient_code: str, timeout_s: float = 30.0, interval_s: float = 2.0
) -> tuple:
    deadline = time.monotonic() + timeout_s
    last_code: str | None = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            last_code = code
            if code == expected_code or code != transient_code:
                return code, err.response["Error"].get("Message")
            time.sleep(interval_s)
        else:
            # An over-permissive target accepting the oversized-tags call is the strongest signal
            # available.
            raise AssertionError(
                f"expected the call to fail with {expected_code!r}, but it SUCCEEDED and "
                f"returned {result!r}"
            )
    raise AssertionError(
        f"never observed a stable error code within {timeout_s}s; last saw {last_code!r}, "
        f"expected {expected_code!r}"
    )


def _wait_for_assume_role(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDenied":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"assume_role never became permitted within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

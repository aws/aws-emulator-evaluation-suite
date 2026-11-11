"""e2e-assume-role-oversized-session-policy-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-assume-role-oversized-session-policy-rejected"
GROUP = "e2e"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole rejects oversized session Tags with PackedPolicyTooLarge and the exact message,
    while small tags on the same role succeed before and after, minting credentials that
    GetCallerIdentity resolves to the assumed-role ARN."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-role-")
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
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, role_name))

    small_tags = [{"Key": "Team", "Value": "engineering"}]

    # IAM trust policies are eventually consistent; poll until the role is assumable at all,
    # using the small control tag set first so a transient AccessDenied doesn't get misread.
    control_resp = _poll_until(
        probe=lambda: _try_assume(sts, role_arn, ctx.unique_name("sess-ctrl-"), Tags=small_tags),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert "Credentials" in control_resp, (
        f"AssumeRole with the small control tag set must issue credentials once the trust "
        f"policy has propagated; got response keys {sorted(control_resp)}"
    )
    assert control_resp["PackedPolicySize"] < 100, (
        f"a small session tag set must pack well under the 100% quota; got "
        f"{control_resp['PackedPolicySize']}"
    )

    # An oversized inline Policy hits its own 2048-char ValidationError first, so session Tags
    # (50 tags, each within its own key/value limits) are used to exceed the packed size.
    oversized_tags = [
        {"Key": f"T{i:03d}" + ("k" * 120), "Value": "v" * 256} for i in range(50)
    ]
    code, message = _client_error(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sess-big-"),
            Tags=oversized_tags,
        )
    )
    assert code == "PackedPolicyTooLarge", code
    assert message == (
        "Serialized token too large for session. Token size of 26092 bytes exceeds the "
        "maximum allowed limit of 4096 bytes."
    ), message

    # Repeated control: the rejection is specific to the oversized tags.
    session_name_2 = ctx.unique_name("sess-ctrl2-")
    control_resp_2 = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=session_name_2, Tags=small_tags
    )
    assert "Credentials" in control_resp_2, (
        f"AssumeRole with a small tag set on the same role must still issue credentials "
        f"after the oversized-tags rejection above; got response keys "
        f"{sorted(control_resp_2)}"
    )

    # The minted credentials must actually authenticate, not merely be present in the response.
    minted = control_resp_2["Credentials"]
    minted_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": minted["AccessKeyId"],
            "aws_secret_access_key": minted["SecretAccessKey"],
            "aws_session_token": minted["SessionToken"],
        },
    )
    identity = minted_sts.get_caller_identity()
    expected_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name_2}"
    assert identity.get("Arn") == expected_arn, (
        f"minted credentials from the post-rejection positive control must be live and "
        f"identify as {expected_arn!r} via an independent GetCallerIdentity call; got "
        f"{identity.get('Arn')!r}"
    )


def _client_error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded where AWS refuses it")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _try_assume(sts_client, role_arn, session_name, **kwargs):
    try:
        return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name, **kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return None
        raise


def _delete_role_if_exists(iam, role_name) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

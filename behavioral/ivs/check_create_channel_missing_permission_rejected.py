"""create-channel-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-channel-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller assuming an IAM role with no attached permissions gets AccessDeniedException
    on CreateChannel and creates nothing, while the test's own (permitted) credentials can
    still create a channel normally."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-ivs-noperm-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # Deliberately: no policy is attached to this role, so it has no IVS permissions at all.

    assumed = _assume_role_with_retry(sts, role_arn, ctx.unique_name("sim2real-ivs-sess-"))
    creds = assumed["Credentials"]
    assumed_arn = assumed["AssumedRoleUser"]["Arn"]
    # ctx.client(creds=...) re-signs with the assumed role's temporary credentials while
    # keeping this target's endpoint and TLS settings, so the restricted call still lands on
    # the emulator under test rather than escaping to real AWS.
    restricted_ivs = ctx.client(
        "ivs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    bad_name = ctx.unique_name("sim2real-ivs-noperm-chan-")
    error = _client_error(
        lambda: _create_channel_after_propagation(restricted_ivs, bad_name)
    )
    assert error["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for an unpermissioned caller, got {error!r}"
    )
    expected_message = (
        f"User: {assumed_arn} is not authorized to perform: ivs:CreateChannel on resource: "
        f"arn:aws:ivs:{ctx.region}:{account_id}:channel/* because no identity-based policy "
        f"allows the ivs:CreateChannel action"
    )
    assert error["Message"] == expected_message, (
        f"unexpected AccessDeniedException message: {error['Message']!r}"
    )

    # Effect absent: nothing was created under the permitted caller's view either.
    ivs = ctx.client("ivs")
    survivors = ivs.list_channels(filterByName=bad_name)["channels"]
    assert survivors == [], (
        f"denied CreateChannel must create nothing, but list_channels found {survivors!r}"
    )

    # Positive control: the normally-permitted caller can create a channel just fine.
    good_name = ctx.unique_name("sim2real-ivs-noperm-good-")
    created = ivs.create_channel(name=good_name, tags={"purpose": "sim2real"})["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=created["arn"]))
    assert created["name"] == good_name, (
        f"expected CreateChannel's own response to echo name {good_name!r}, got {created['name']!r}"
    )

    # Independent terminal read: the permitted caller's channel is really there, at the
    # destination, through a different operation than the one that created it.
    fetched = ivs.get_channel(arn=created["arn"])["channel"]
    assert fetched["name"] == good_name, (
        f"expected GetChannel to read back name {good_name!r}, got {fetched['name']!r}"
    )


def _assume_role_with_retry(sts, role_arn: str, session_name: str, timeout_s: float = 30.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        except ClientError as e:
            # Freshly-created roles can take a few seconds to become assumable.
            last_error = e
            time.sleep(2.0)
    raise AssertionError(f"could not assume freshly-created role in time: {last_error}")


def _create_channel_after_propagation(client, name: str, timeout_s: float = 20.0):
    """Retries ONLY `UnrecognizedClientException`: freshly assumed-role credentials can
    read as unrecognized by IVS's control plane for a few seconds after AssumeRole, before
    IAM's global replication catches up, even though the role is already assumable. The
    AccessDeniedException under test is returned immediately once credentials are
    recognized, so it propagates unchanged -- this never masks the assertion."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.create_channel(name=name)
        except ClientError as e:
            if (
                e.response["Error"]["Code"] == "UnrecognizedClientException"
                and time.monotonic() < deadline
            ):
                time.sleep(1.0)
                continue
            raise


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(
        f"expected the call to be rejected with AccessDeniedException, but it succeeded "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

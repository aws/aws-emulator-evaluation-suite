"""get-ice-server-config-denied-without-iam-permission."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-ice-server-config-denied-without-iam-permission"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role allowed GetIceServerConfig can call it, an added explicit Deny makes it fail with
    AccessDeniedException and its exact message, removing only the Deny restores it, and the owner succeeds
    throughout."""
    kv = ctx.client("kinesisvideo")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    name = ctx.unique_name("sim2real-kvsig-iam-")
    arn = kv.create_signaling_channel(ChannelName=name, ChannelType="SINGLE_MASTER")["ChannelARN"]
    ctx.on_cleanup(lambda: kv.delete_signaling_channel(ChannelARN=arn))
    _wait_channel_status(ctx, name, "ACTIVE")

    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    # sanity: owner can call it before we even touch IAM
    ok = sig.get_ice_server_config(ChannelARN=arn)
    assert len(ok["IceServerList"]) > 0, (
        f"positive control failed before any IAM change: expected a non-empty IceServerList, "
        f"got {ok['IceServerList']!r}"
    )

    role_name = ctx.unique_name("sim2real-kvsig-noperm-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # the baseline grant: WITHOUT this, "denied" would be indistinguishable from "never had
    # permission at all" -- an explicit Deny only means something if it overrides a real Allow.
    allow_policy_name = "allow-get-ice-server-config"
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "kinesisvideo:GetIceServerConfig", "Resource": arn}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=allow_policy_name, PolicyDocument=json.dumps(allow_policy)
    )
    ctx.on_cleanup(lambda: _drop_role_policy(iam, role_name, allow_policy_name))

    deny_policy_name = "deny-get-ice-server-config"
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "kinesisvideo:GetIceServerConfig", "Resource": "*"}],
    }

    session_name = ctx.unique_name("sess-")

    def _assume():
        return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]

    # newly created roles can take a few seconds to become assumable
    creds = _poll_until(_assume, lambda c: c is not None, timeout_s=60.0, interval_s=3.0)

    scoped_client = ctx.client(
        "kinesis-video-signaling",
        endpoint_url=https_endpoint,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    def _scoped_call():
        return _client_error(lambda: scoped_client.get_ice_server_config(ChannelARN=arn))

    # positive control on the SAME identity: the Allow alone (no Deny yet) must let it through --
    # this is what makes the coming rejection mean "the Deny did it", not "this role never could"
    allowed_code = _poll_until(_scoped_call, lambda c: c is None, timeout_s=60.0, interval_s=3.0)
    assert allowed_code is None, (
        f"expected the Allow-only role to succeed before any Deny is attached, got {allowed_code!r}"
    )

    # break exactly one thing: an explicit Deny for the identical action, on top of the same Allow
    iam.put_role_policy(
        RoleName=role_name, PolicyName=deny_policy_name, PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(lambda: _drop_role_policy(iam, role_name, deny_policy_name))

    # a freshly attached Deny policy can also take a few seconds to take effect
    denial = _poll_until(_scoped_call, lambda c: c is not None, timeout_s=60.0, interval_s=3.0)
    # IAM-level Deny is enforced by the common AWS authorization layer *before* the request
    # reaches the kinesis-video-signaling service logic, so it surfaces as the generic
    # AccessDeniedException (403) -- not the service-modeled NotAuthorizedException, which is
    # reserved for other authorization failures raised by the service itself.
    assert denial["Code"] == "AccessDeniedException", f"expected AccessDeniedException, got {denial!r}"
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: kinesisvideo:GetIceServerConfig on resource: {arn} with an "
        f"explicit deny in an identity-based policy"
    )
    assert denial["Message"] == expected, f"expected message {expected!r}, got {denial!r}"

    # restore: remove ONLY the Deny (the Allow is untouched) and prove the SAME identity's
    # identical call now succeeds -- this is the beat that shows the Deny, not a missing grant,
    # caused the rejection. Measured against real AWS: Deny removal propagates slower than Deny
    # attachment, so this leg gets a longer window than the break leg above.
    _drop_role_policy(iam, role_name, deny_policy_name)
    restored_code = _poll_until(_scoped_call, lambda c: c is None, timeout_s=120.0, interval_s=5.0)
    assert restored_code is None, (
        f"expected the identical call from the same role to succeed once the Deny is removed and "
        f"only the Allow remains, got error {restored_code!r}"
    )

    # positive control: the original, fully permissioned caller still succeeds throughout
    still_ok = sig.get_ice_server_config(ChannelARN=arn)
    assert len(still_ok["IceServerList"]) > 0, (
        f"positive control failed after the IAM deny/restore cycle: expected a non-empty "
        f"IceServerList, got {still_ok['IceServerList']!r}"
    )


def _drop_role_policy(iam, role_name, policy_name):
    """Teardown-only: the body detaches the deny itself, so tolerate it already being gone."""
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_channel_status(ctx, name, target_status, timeout_s=60.0, interval_s=1.5):
    kv = ctx.client("kinesisvideo")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kv.describe_signaling_channel(ChannelName=name)["ChannelInfo"]
        last = info.get("ChannelStatus")
        if last == target_status:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"channel {name!r} did not reach status {target_status!r}; last seen {last!r}")


def _get_endpoint(ctx, channel_arn, protocol, role):
    kv = ctx.client("kinesisvideo")
    resp = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": [protocol], "Role": role},
    )
    for entry in resp["ResourceEndpointList"]:
        if entry["Protocol"] == protocol:
            return entry["ResourceEndpoint"]
    raise AssertionError(f"no {protocol} endpoint returned for channel {channel_arn}")


def _client_error(fn):
    """The error a refused call returns, or None when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except Exception:  # noqa: BLE001 - transient propagation errors (e.g. AssumeRole 403)
            last = None
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

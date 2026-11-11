"""deploy-ivs-channel-stream-key-playback-key-pair-and-restriction-policy-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "deploy-ivs-channel-stream-key-playback-key-pair-and-restriction-policy-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ivs"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

def _public_key_pem() -> str:
    """A fresh ECDSA P-384 public key per run; the private half is discarded at once."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"]) from exc
    return ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def _key_pairs(ivs, name: str) -> list[dict]:
    return [k for k in paginate(ivs, "list_playback_key_pairs", "keyPairs") if k["name"] == name]


def _policies(ivs, name: str) -> list[dict]:
    """The restriction policies named ``name``, every page (the op has no paginator)."""
    kw, out = {}, []
    while True:
        page = ivs.list_playback_restriction_policies(**kw)
        out += [p for p in page["playbackRestrictionPolicies"] if p["name"] == name]
        if not page.get("nextToken"):
            return out
        kw["nextToken"] = page["nextToken"]


def _template(channel_name: str, kp_name: str, policy_name: str, key_pem: str, *,
              with_stream_key: bool = True) -> str:
    resources = {
        "Channel": {"Type": "AWS::IVS::Channel",
                    "Properties": {"Name": channel_name, "Type": "BASIC"}},
        "KeyPair": {"Type": "AWS::IVS::PlaybackKeyPair",
                    "Properties": {"Name": kp_name, "PublicKeyMaterial": key_pem}},
        "Policy": {"Type": "AWS::IVS::PlaybackRestrictionPolicy", "Properties": {
            "Name": policy_name,
            "AllowedCountries": ["US"],
            "AllowedOrigins": ["https://sim2real.example.com"],
            "EnableStrictOriginEnforcement": True,
        }},
    }
    outputs = {
        "ChannelRef": {"Value": {"Ref": "Channel"}},
        "ChannelArn": {"Value": {"Fn::GetAtt": ["Channel", "Arn"]}},
        "ChannelPlaybackUrl": {"Value": {"Fn::GetAtt": ["Channel", "PlaybackUrl"]}},
        "ChannelIngestEndpoint": {"Value": {"Fn::GetAtt": ["Channel", "IngestEndpoint"]}},
        "KeyPairRef": {"Value": {"Ref": "KeyPair"}},
        "KeyPairFingerprint": {"Value": {"Fn::GetAtt": ["KeyPair", "Fingerprint"]}},
        "PolicyRef": {"Value": {"Ref": "Policy"}},
    }
    if with_stream_key:
        resources["StreamKey"] = {"Type": "AWS::IVS::StreamKey",
                                  "Properties": {"ChannelArn": {"Fn::GetAtt": ["Channel", "Arn"]}}}
        # The key's Value is an ingest secret: never an Output.
        outputs["StreamKeyRef"] = {"Value": {"Ref": "StreamKey"}}
    return json.dumps({"Resources": resources, "Outputs": outputs})


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack's IVS Channel, StreamKey, PlaybackKeyPair and PlaybackRestrictionPolicy read back.

    Each Ref equals the ARN IVS lists with every templated property and GetAtt; an update dropping
    the stream key removes it while the channel answers, and the stack delete removes the rest.
    """
    cfn = ctx.client("cloudformation")
    ivs = ctx.client("ivs")
    channel_name = ctx.unique_name("sim2real-behav-ivsall-chan-")
    kp_name = ctx.unique_name("sim2real-behav-ivsall-kp-")
    policy_name = ctx.unique_name("sim2real-behav-ivsall-pol-")
    key_pem = _public_key_pem()
    names = (channel_name, kp_name, policy_name, key_pem)

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-ivsall-"),
                            _template(*names))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Each Ref against an independent read: the IVS list entry under the declared name.
    channels = [c["arn"] for c in paginate(ivs, "list_channels", "channels",
                                           filterByName=channel_name)
                if c["name"] == channel_name]
    assert channels == [out["ChannelRef"]] == [out["ChannelArn"]], f"IVS lists {channels!r}"
    channel = ivs.get_channel(arn=channels[0])["channel"]
    got = (channel["name"], channel["type"], channel["playbackUrl"], channel["ingestEndpoint"])
    want = (channel_name, "BASIC", out["ChannelPlaybackUrl"], out["ChannelIngestEndpoint"])
    assert got == want, f"channel reads {got!r}, expected {want!r}"

    keys = [k["arn"] for k in paginate(ivs, "list_stream_keys", "streamKeys",
                                       channelArn=channel["arn"])]
    assert keys == [out["StreamKeyRef"]], f"IVS lists stream keys {keys!r}"
    stream_key = ivs.get_stream_key(arn=keys[0])["streamKey"]
    assert stream_key["channelArn"] == channel["arn"], f"stream key reads {stream_key['arn']!r}"

    pairs = [k["arn"] for k in _key_pairs(ivs, kp_name)]
    assert pairs == [out["KeyPairRef"]], f"IVS lists key pairs {pairs!r}"
    key_pair = ivs.get_playback_key_pair(arn=pairs[0])["keyPair"]
    got = (key_pair["name"], key_pair["fingerprint"])
    assert got == (kp_name, out["KeyPairFingerprint"]), f"key pair reads {got!r}"

    policies = [p["arn"] for p in _policies(ivs, policy_name)]
    assert policies == [out["PolicyRef"]], f"IVS lists policies {policies!r}"
    policy = ivs.get_playback_restriction_policy(arn=policies[0])["playbackRestrictionPolicy"]
    got = (policy["name"], policy["allowedCountries"], policy["allowedOrigins"],
           policy["enableStrictOriginEnforcement"])
    want = (policy_name, ["US"], ["https://sim2real.example.com"], True)
    assert got == want, f"restriction policy reads {got!r}, expected {want!r}"

    # Child before parent: an update drops only the stream key; the same channel answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(*names, with_stream_key=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"stream-key-removing update ended {status!r}"
    left = paginate(ivs, "list_stream_keys", "streamKeys", channelArn=channel["arn"])
    assert left == [], f"after dropping the stream key IVS lists {left!r}"
    key_gone = ("ResourceNotFoundException", f"Resource: {keys[0]} not found")
    expect_error(lambda: ivs.get_stream_key(arn=keys[0]), *key_gone)
    kept = ivs.get_channel(arn=channel["arn"])["channel"]["name"]
    assert kept == channel_name, f"channel after dropping the stream key reads {kept!r}"

    delete_stack(cfn, stack_id)
    for arn, getter in ((channel["arn"], ivs.get_channel), (pairs[0], ivs.get_playback_key_pair),
                        (policies[0], ivs.get_playback_restriction_policy)):
        gone = ("ResourceNotFoundException", f"Resource: {arn} not found")
        expect_error(lambda arn=arn, getter=getter: getter(arn=arn), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

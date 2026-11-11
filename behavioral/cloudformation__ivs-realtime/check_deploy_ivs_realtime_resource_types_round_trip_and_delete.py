"""deploy-ivs-realtime-resource-types-round-trip-and-delete."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-ivs-realtime-resource-types-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ivs-realtime"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_VIDEO = {"Width": 1280, "Height": 720, "Framerate": 30, "Bitrate": 2500000}


def _generate_ec_public_key_pem() -> str:
    # IVS real-time ImportPublicKey requires an ECDSA/secp384r1 key, not P-256 or RSA.
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "priv.pem")
        pub = os.path.join(d, "pub.pem")
        subprocess.run(
            ["openssl", "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", priv],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-in", priv, "-pubout", "-out", pub],
            check=True, capture_output=True,
        )
        with open(pub) as f:
            return f.read()


def _template(names: dict, pem: str, tag_value: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": names["bucket"]}},
            "Encoder": {
                "Type": "AWS::IVS::EncoderConfiguration",
                "Properties": {"Name": names["encoder"], "Video": _VIDEO, "Tags": t},
            },
            "PubKey": {
                "Type": "AWS::IVS::PublicKey",
                "Properties": {"Name": names["pubkey"], "PublicKeyMaterial": pem, "Tags": t},
            },
            "Stage": {
                "Type": "AWS::IVS::Stage",
                "Properties": {"Name": names["stage"], "Tags": t},
            },
            "Ingest": {
                "Type": "AWS::IVS::IngestConfiguration",
                "Properties": {"Name": names["ingest"], "IngestProtocol": "RTMPS", "Tags": t},
            },
            "Storage": {
                "Type": "AWS::IVS::StorageConfiguration",
                "Properties": {
                    "Name": names["storage"],
                    "S3": {"BucketName": {"Ref": "Bucket"}},
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "Bucket"}},
            "EncoderRef": {"Value": {"Ref": "Encoder"}},
            "EncoderArn": {"Value": {"Fn::GetAtt": ["Encoder", "Arn"]}},
            "PubKeyRef": {"Value": {"Ref": "PubKey"}},
            "PubKeyArn": {"Value": {"Fn::GetAtt": ["PubKey", "Arn"]}},
            "PubKeyFingerprint": {"Value": {"Fn::GetAtt": ["PubKey", "Fingerprint"]}},
            "StageRef": {"Value": {"Ref": "Stage"}},
            "StageArn": {"Value": {"Fn::GetAtt": ["Stage", "Arn"]}},
            "StageActiveSessionId": {"Value": {"Fn::GetAtt": ["Stage", "ActiveSessionId"]}},
            "IngestRef": {"Value": {"Ref": "Ingest"}},
            "IngestArn": {"Value": {"Fn::GetAtt": ["Ingest", "Arn"]}},
            "IngestParticipantId": {"Value": {"Fn::GetAtt": ["Ingest", "ParticipantId"]}},
            "IngestState": {"Value": {"Fn::GetAtt": ["Ingest", "State"]}},
            "StorageRef": {"Value": {"Ref": "Storage"}},
            "StorageArn": {"Value": {"Fn::GetAtt": ["Storage", "Arn"]}},
        },
    })


def _md5_colon_hex(pem: str) -> str:
    import base64
    import hashlib

    der = b"".join(
        base64.b64decode(line)
        for line in pem.strip().splitlines()
        if line and "-----" not in line
    )
    return ":".join(f"{b:02x}" for b in hashlib.md5(der).digest())


def _listed_arns(call, key: str, name: str) -> list[str]:
    """The arns of every summary named ``name`` in an ivs-realtime list, following nextToken
    (botocore has no paginator for every one of these lists)."""
    arns: list[str] = []
    kwargs: dict = {}
    while True:
        page = call(**kwargs)
        arns.extend(item["arn"] for item in page.get(key, []) if item.get("name") == name)
        if not page.get("nextToken"):
            return arns
        kwargs["nextToken"] = page["nextToken"]


def _user_tags(tags_: dict) -> dict:
    """Tags without the aws:-prefixed system tags CloudFormation adds."""
    return {k: v for k, v in tags_.items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack provisions IVS real-time EncoderConfiguration, PublicKey, Stage,
    IngestConfiguration and StorageConfiguration; each Ref is ivs-realtime's listed arn, every GetAtt
    and tag matches ivs-realtime's own read, and the stack delete removes all five.

    Reference: https://docs.aws.amazon.com/IVS/latest/RealTimeUserGuide/getting-started-cloudformation.html
    """
    cfn = ctx.client("cloudformation")
    ivsrt = ctx.client("ivs-realtime")
    stack = ctx.unique_name("sim2real-cfnivsrt-")
    names = {
        "bucket": ctx.unique_name("sim2real-cfnivsrt-").lower()[:63],
        "encoder": ctx.unique_name("sim2real-cfnivsrt-enc-"),
        "pubkey": ctx.unique_name("sim2real-cfnivsrt-pk-"),
        "stage": ctx.unique_name("sim2real-cfnivsrt-stg-"),
        "ingest": ctx.unique_name("sim2real-cfnivsrt-ing-"),
        "storage": ctx.unique_name("sim2real-cfnivsrt-store-"),
    }
    pem = _generate_ec_public_key_pem()

    stack_id = create_stack(ctx, cfn, stack, _template(names, pem, CHECK))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    want_tags = {"sim2real": stack, "sim2real-check": CHECK}

    # Each Ref against ivs-realtime's own listing by the template's name, an independent read.
    for kind, call, key, ref in (
        ("encoder", ivsrt.list_encoder_configurations, "encoderConfigurations", "EncoderRef"),
        ("pubkey", ivsrt.list_public_keys, "publicKeys", "PubKeyRef"),
        ("stage", ivsrt.list_stages, "stages", "StageRef"),
        ("ingest", ivsrt.list_ingest_configurations, "ingestConfigurations", "IngestRef"),
        ("storage", ivsrt.list_storage_configurations, "storageConfigurations", "StorageRef"),
    ):
        listed = _listed_arns(call, key, names[kind])
        assert listed == [outputs[ref]], (
            f"{key} listed arns {listed!r} for {names[kind]!r}, expected the Ref {outputs[ref]!r}"
        )

    # EncoderConfiguration: Ref is the Arn (its only read-only attribute); Video round-trips.
    assert outputs["EncoderRef"] == outputs["EncoderArn"], (
        f"Encoder Ref {outputs['EncoderRef']!r} != GetAtt Arn {outputs['EncoderArn']!r}"
    )
    encoder = ivsrt.get_encoder_configuration(arn=outputs["EncoderArn"])["encoderConfiguration"]
    assert encoder["arn"] == outputs["EncoderArn"], (
        f"GetEncoderConfiguration arn {encoder['arn']!r} != stack output {outputs['EncoderArn']!r}"
    )
    assert encoder["name"] == names["encoder"], f"encoder name {encoder['name']!r}"
    assert encoder["video"] == {
        "width": _VIDEO["Width"], "height": _VIDEO["Height"],
        "framerate": float(_VIDEO["Framerate"]), "bitrate": _VIDEO["Bitrate"],
    }, f"encoder video {encoder['video']!r} does not match the template's Video property"
    assert _user_tags(encoder.get("tags", {})) == want_tags, f"encoder tags {encoder.get('tags')!r}"

    # PublicKey: Ref is the Arn; Fingerprint is a distinct read-only attribute.
    assert outputs["PubKeyRef"] == outputs["PubKeyArn"], (
        f"PubKey Ref {outputs['PubKeyRef']!r} != GetAtt Arn {outputs['PubKeyArn']!r}"
    )
    pubkey = ivsrt.get_public_key(arn=outputs["PubKeyArn"])["publicKey"]
    assert pubkey["arn"] == outputs["PubKeyArn"], f"GetPublicKey arn {pubkey['arn']!r}"
    assert pubkey["name"] == names["pubkey"], f"public key name {pubkey['name']!r}"
    assert pubkey["publicKeyMaterial"].strip() == pem.strip(), (
        "GetPublicKey publicKeyMaterial does not match the template's PublicKeyMaterial"
    )
    expected_fingerprint = _md5_colon_hex(pem)
    assert pubkey["fingerprint"] == expected_fingerprint, (
        f"fingerprint {pubkey['fingerprint']!r} != expected md5 colon-hex {expected_fingerprint!r}"
    )
    assert outputs["PubKeyFingerprint"] == pubkey["fingerprint"], (
        f"GetAtt Fingerprint {outputs['PubKeyFingerprint']!r} != GetPublicKey "
        f"{pubkey['fingerprint']!r}"
    )
    assert _user_tags(pubkey.get("tags", {})) == want_tags, f"public key tags {pubkey.get('tags')!r}"

    # Stage: Ref is the Arn; ActiveSessionId is a distinct read-only attribute.
    assert outputs["StageRef"] == outputs["StageArn"], (
        f"Stage Ref {outputs['StageRef']!r} != GetAtt Arn {outputs['StageArn']!r}"
    )
    stage = ivsrt.get_stage(arn=outputs["StageArn"])["stage"]
    assert stage["arn"] == outputs["StageArn"], f"GetStage arn {stage['arn']!r}"
    assert stage["name"] == names["stage"], f"stage name {stage['name']!r}"
    assert stage["activeSessionId"] == outputs["StageActiveSessionId"] == "", (
        f"activeSessionId: GetStage={stage['activeSessionId']!r} "
        f"GetAtt={outputs['StageActiveSessionId']!r}, expected both ''"
    )
    assert _user_tags(stage.get("tags", {})) == want_tags, f"stage tags {stage.get('tags')!r}"

    # IngestConfiguration: Ref is the Arn; ParticipantId and State are distinct read-only
    # attributes. The stream key is a credential: it stays out of Outputs and messages.
    assert outputs["IngestRef"] == outputs["IngestArn"], (
        f"Ingest Ref {outputs['IngestRef']!r} != GetAtt Arn {outputs['IngestArn']!r}"
    )
    ingest = ivsrt.get_ingest_configuration(arn=outputs["IngestArn"])["ingestConfiguration"]
    assert ingest["arn"] == outputs["IngestArn"], f"GetIngestConfiguration arn {ingest['arn']!r}"
    assert ingest["name"] == names["ingest"], f"ingest name {ingest['name']!r}"
    assert ingest["ingestProtocol"] == "RTMPS", f"ingestProtocol {ingest['ingestProtocol']!r}"
    assert ingest["participantId"] == outputs["IngestParticipantId"] and ingest["participantId"], (
        f"participantId: GetIngestConfiguration={ingest['participantId']!r} "
        f"GetAtt={outputs['IngestParticipantId']!r}"
    )
    assert ingest["state"] == outputs["IngestState"], (
        f"state: GetIngestConfiguration={ingest['state']!r} GetAtt={outputs['IngestState']!r}"
    )
    assert isinstance(ingest.get("streamKey"), str) and ingest["streamKey"], (
        "GetIngestConfiguration returned no streamKey for the ingest configuration"
    )
    assert _user_tags(ingest.get("tags", {})) == want_tags, f"ingest tags {ingest.get('tags')!r}"

    # StorageConfiguration: Ref is the Arn (its only read-only attribute); S3.BucketName
    # round-trips to the bucket the same stack created.
    assert outputs["StorageRef"] == outputs["StorageArn"], (
        f"Storage Ref {outputs['StorageRef']!r} != GetAtt Arn {outputs['StorageArn']!r}"
    )
    storage = ivsrt.get_storage_configuration(arn=outputs["StorageArn"])["storageConfiguration"]
    assert storage["arn"] == outputs["StorageArn"], f"GetStorageConfiguration arn {storage['arn']!r}"
    assert storage["name"] == names["storage"], f"storage name {storage['name']!r}"
    assert storage["s3"]["bucketName"] == outputs["BucketName"], (
        f"storage s3.bucketName {storage['s3']['bucketName']!r} != stack's bucket "
        f"{outputs['BucketName']!r}"
    )
    assert _user_tags(storage.get("tags", {})) == want_tags, f"storage tags {storage.get('tags')!r}"

    arns = {
        "encoder": outputs["EncoderArn"], "pubkey": outputs["PubKeyArn"],
        "stage": outputs["StageArn"], "ingest": outputs["IngestArn"],
        "storage": outputs["StorageArn"],
    }

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    gone = {kind: ("ResourceNotFoundException", f"Resource: {arn} not found")
            for kind, arn in arns.items()}
    expect_error(lambda: ivsrt.get_encoder_configuration(arn=arns["encoder"]), *gone["encoder"])
    expect_error(lambda: ivsrt.get_public_key(arn=arns["pubkey"]), *gone["pubkey"])
    expect_error(lambda: ivsrt.get_stage(arn=arns["stage"]), *gone["stage"])
    expect_error(lambda: ivsrt.get_ingest_configuration(arn=arns["ingest"]), *gone["ingest"])
    expect_error(lambda: ivsrt.get_storage_configuration(arn=arns["storage"]),
                 *gone["storage"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

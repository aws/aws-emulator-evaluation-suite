"""deploy-cloudfront-publickey-and-keygroup-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from behavioral_harness import tags

CHECK = "deploy-cloudfront-publickey-and-keygroup-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront"]

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

_NOT_FOUND_PK = ("NoSuchPublicKey", "The specified CloudFront public key does not exist.")
_NOT_FOUND_KG = ("NoSuchResource", "The specified key group does not exist.")


def _public_key_pem() -> str:
    """A fresh per-run RSA-2048 public key PEM (no key material is reused across runs)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _template(caller_ref, pk_name, pem, kg_name, with_group=True):
    resources = {
        "PublicKey": {"Type": "AWS::CloudFront::PublicKey", "Properties": {
            "PublicKeyConfig": {
                "CallerReference": caller_ref, "Name": pk_name, "EncodedKey": pem,
            },
        }},
    }
    outputs = {
        "PublicKeyRef": {"Value": {"Ref": "PublicKey"}},
        "PublicKeyCreatedTime": {"Value": {"Fn::GetAtt": ["PublicKey", "CreatedTime"]}},
    }
    if with_group:
        resources["KeyGroup"] = {"Type": "AWS::CloudFront::KeyGroup", "Properties": {
            "KeyGroupConfig": {"Name": kg_name, "Items": [{"Ref": "PublicKey"}]},
        }}
        outputs["KeyGroupRef"] = {"Value": {"Ref": "KeyGroup"}}
        outputs["KeyGroupLastModifiedTime"] = {
            "Value": {"Fn::GetAtt": ["KeyGroup", "LastModifiedTime"]}
        }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _iso_ms(dt) -> str:
    """CloudFront's millisecond-precision ISO8601 ``Z`` format, matching a GetAtt string output."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation PublicKey and the KeyGroup that holds it read back through CloudFront.

    Ref, GetAtt and every templated property match an independent ListPublicKeys/ListKeyGroups
    read; an update dropping the KeyGroup removes it first, then the stack delete removes the key.
    """
    cfront = ctx.client("cloudfront")
    cf = ctx.client("cloudformation")
    caller_ref = ctx.unique_name("sim2real-cfnpk-cr-")
    pk_name = ctx.unique_name("sim2real-cfnpk-")
    kg_name = ctx.unique_name("sim2real-cfnkg-")
    pem = _public_key_pem()

    stack_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnpkkg-"),
                            _template(caller_ref, pk_name, pem, kg_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    pk = cfront.get_public_key(Id=out["PublicKeyRef"])["PublicKey"]
    assert pk["Id"] == out["PublicKeyRef"], f"GetPublicKey Id {pk['Id']!r} != Ref {out['PublicKeyRef']!r}"
    cfg = pk["PublicKeyConfig"]
    got_pk_props = {"CallerReference": cfg["CallerReference"], "Name": cfg["Name"],
                    "EncodedKey": cfg["EncodedKey"]}
    assert got_pk_props == {"CallerReference": caller_ref, "Name": pk_name, "EncodedKey": pem}, (
        f"PublicKeyConfig read back {got_pk_props!r}"
    )
    assert _iso_ms(pk["CreatedTime"]) == out["PublicKeyCreatedTime"], (
        f"GetPublicKey CreatedTime {_iso_ms(pk['CreatedTime'])!r} != "
        f"GetAtt {out['PublicKeyCreatedTime']!r}"
    )

    # Ref against an independent read (ListPublicKeys), never a read keyed by the Ref. No botocore
    # paginator result key is flat here (Items nests under PublicKeyList): paginate by hand.
    all_pk = []
    marker = ""
    while True:
        page = cfront.list_public_keys(Marker=marker) if marker else cfront.list_public_keys()
        all_pk.extend(page["PublicKeyList"]["Items"])
        marker = page["PublicKeyList"].get("NextMarker")
        if not marker:
            break
    listed_pk = [p for p in all_pk if p["Name"] == pk_name]
    assert len(listed_pk) == 1, f"ListPublicKeys found {listed_pk!r} for Name {pk_name!r}"
    assert listed_pk[0]["Id"] == out["PublicKeyRef"], (
        f"ListPublicKeys Id {listed_pk[0]['Id']!r} != Ref {out['PublicKeyRef']!r}"
    )
    assert listed_pk[0]["EncodedKey"] == pem, "ListPublicKeys EncodedKey does not match the template"

    kg = cfront.get_key_group(Id=out["KeyGroupRef"])["KeyGroup"]
    assert kg["Id"] == out["KeyGroupRef"], f"GetKeyGroup Id {kg['Id']!r} != Ref {out['KeyGroupRef']!r}"
    kg_cfg = kg["KeyGroupConfig"]
    assert kg_cfg["Name"] == kg_name, f"KeyGroupConfig Name {kg_cfg['Name']!r} != {kg_name!r}"
    assert kg_cfg["Items"] == [out["PublicKeyRef"]], (
        f"KeyGroupConfig Items {kg_cfg['Items']!r} != [{out['PublicKeyRef']!r}]"
    )
    assert _iso_ms(kg["LastModifiedTime"]) == out["KeyGroupLastModifiedTime"], (
        f"GetKeyGroup LastModifiedTime {_iso_ms(kg['LastModifiedTime'])!r} != "
        f"GetAtt {out['KeyGroupLastModifiedTime']!r}"
    )

    # ListKeyGroups has no botocore paginator and nests Items under KeyGroupList: paginate by hand.
    listed_kg = []
    marker = ""
    while True:
        page = cfront.list_key_groups(Marker=marker) if marker else cfront.list_key_groups()
        listed_kg.extend(page["KeyGroupList"]["Items"])
        marker = page["KeyGroupList"].get("NextMarker")
        if not marker:
            break
    matches = [g["KeyGroup"] for g in listed_kg if g["KeyGroup"]["KeyGroupConfig"]["Name"] == kg_name]
    assert len(matches) == 1, f"ListKeyGroups found {matches!r} for Name {kg_name!r}"
    assert matches[0]["Id"] == out["KeyGroupRef"], (
        f"ListKeyGroups Id {matches[0]['Id']!r} != Ref {out['KeyGroupRef']!r}"
    )

    # Child before parent: an update dropping the KeyGroup removes it while the same PublicKey
    # (CreatedTime unchanged) still answers.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(
        caller_ref, pk_name, pem, kg_name, with_group=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"key-group-removing update ended {status!r}"
    expect_error(lambda: cfront.get_key_group(Id=out["KeyGroupRef"]), *_NOT_FOUND_KG)
    after = cfront.get_public_key(Id=out["PublicKeyRef"])["PublicKey"]
    assert after["CreatedTime"] == pk["CreatedTime"], (
        f"the PublicKey CreatedTime changed across the update: {after['CreatedTime']!r}"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: cfront.get_public_key(Id=out["PublicKeyRef"]), *_NOT_FOUND_PK)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

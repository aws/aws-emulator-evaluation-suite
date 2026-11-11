"""layer-version-permission-duplicate-statement-rejected."""
from __future__ import annotations

import io
import json
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "layer-version-permission-duplicate-statement-rejected"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Adding a layer version permission with a StatementId that already exists is rejected,
    the rejected call leaves the policy unchanged, and the identical call succeeds once the
    conflicting statement is removed.
    """
    lam = ctx.client("lambda")
    layer = _publish_layer(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    statement_id = "sim2real-dup-grant"

    added = lam.add_layer_version_permission(
        LayerName=layer["name"],
        VersionNumber=layer["version"],
        StatementId=statement_id,
        Action="lambda:GetLayerVersion",
        Principal=account_id,
    )
    ctx.on_cleanup(lambda: _remove_permission_ignore(lam, layer["name"], layer["version"], statement_id))
    added_statement = json.loads(added["Statement"])
    assert added_statement["Sid"] == statement_id, f"expected Sid {statement_id!r}, got {added_statement!r}"

    policy_before = _policy_sids(lam, layer["name"], layer["version"])
    assert policy_before == {statement_id}, f"expected exactly {{{statement_id!r}}} in policy, got {policy_before}"

    dup_code, dup_msg = _error(
        lambda: lam.add_layer_version_permission(
            LayerName=layer["name"],
            VersionNumber=layer["version"],
            StatementId=statement_id,
            Action="lambda:GetLayerVersion",
            Principal=account_id,
        )
    )
    assert dup_code == "ResourceConflictException", f"expected ResourceConflictException, got {dup_code}"
    expected_dup = (
        f"The statement id ({statement_id}) provided already exists. Please provide a new statement id, "
        f"or remove the existing statement."
    )
    assert dup_msg == expected_dup, f"expected message {expected_dup!r}, got {dup_msg!r}"

    policy_after_conflict = _policy_sids(lam, layer["name"], layer["version"])
    assert policy_after_conflict == policy_before, (
        f"rejected duplicate must not change the policy: before={policy_before}, after={policy_after_conflict}"
    )

    lam.remove_layer_version_permission(
        LayerName=layer["name"], VersionNumber=layer["version"], StatementId=statement_id
    )
    gone_code, gone_msg = _error(
        lambda: lam.get_layer_version_policy(LayerName=layer["name"], VersionNumber=layer["version"])
    )
    assert gone_code == "ResourceNotFoundException", f"expected policy gone after remove, got {gone_code}"
    expected_gone = f"Layer version {layer['arn']} does not have any resource policy."
    assert gone_msg == expected_gone, f"expected message {expected_gone!r}, got {gone_msg!r}"

    restored = lam.add_layer_version_permission(
        LayerName=layer["name"],
        VersionNumber=layer["version"],
        StatementId=statement_id,
        Action="lambda:GetLayerVersion",
        Principal=account_id,
    )
    restored_statement = json.loads(restored["Statement"])
    assert restored_statement["Sid"] == statement_id, (
        f"identical call must succeed once the conflicting statement is gone, got {restored_statement!r}"
    )


def _policy_sids(lam, layer_name: str, version: int) -> set:
    policy = lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version)
    doc = json.loads(policy["Policy"])
    return {s["Sid"] for s in doc["Statement"]}


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _layer_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/marker.txt", "sim2real behavioral layer content\n")
    return buf.getvalue()


def _publish_layer(ctx) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-layerdup-")
    resp = lam.publish_layer_version(
        LayerName=name,
        Content={"ZipFile": _layer_zip_bytes()},
        CompatibleRuntimes=["python3.12"],
    )
    version = resp["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=name, VersionNumber=version))
    return {"name": name, "version": version, "arn": resp["LayerVersionArn"]}


def _remove_permission_ignore(lam, layer_name: str, version: int, statement_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.remove_layer_version_permission(
            LayerName=layer_name, VersionNumber=version, StatementId=statement_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

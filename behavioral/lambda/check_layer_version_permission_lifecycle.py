"""layer-version-permission-lifecycle."""
from __future__ import annotations

import io
import json
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "layer-version-permission-lifecycle"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Adding/removing a layer version permission statement is reflected in and cleared from GetLayerVersionPolicy."""
    lam = ctx.client("lambda")
    layer = _publish_layer(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    statement_id = "sim2real-grant"

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
    expected_principals = {account_id, f"arn:aws:iam::{account_id}:root"}
    principal_aws = added_statement["Principal"]["AWS"] if isinstance(added_statement["Principal"], dict) else added_statement["Principal"]
    assert principal_aws in expected_principals, f"unexpected principal: {principal_aws!r}"

    policy = lam.get_layer_version_policy(LayerName=layer["name"], VersionNumber=layer["version"])
    policy_doc = json.loads(policy["Policy"])
    sids = {s["Sid"] for s in policy_doc["Statement"]}
    assert statement_id in sids, "granted statement missing from GetLayerVersionPolicy"

    lam.remove_layer_version_permission(
        LayerName=layer["name"], VersionNumber=layer["version"], StatementId=statement_id
    )

    code, message = _error(
        lambda: lam.get_layer_version_policy(LayerName=layer["name"], VersionNumber=layer["version"])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_gone = f"Layer version {layer['arn']} does not have any resource policy."
    assert message == expected_gone, f"expected message {expected_gone!r}, got {message!r}"

    remove_again_code, remove_again_msg = _error(
        lambda: lam.remove_layer_version_permission(
            LayerName=layer["name"], VersionNumber=layer["version"], StatementId=statement_id
        )
    )
    assert remove_again_code == "ResourceNotFoundException", (
        f"expected removing the already-removed statement to fail with ResourceNotFoundException, "
        f"got {remove_again_code}"
    )
    assert remove_again_msg == "No policy is associated with the given resource.", (
        f"unexpected message removing an already-removed statement: {remove_again_msg!r}"
    )

    readded = lam.add_layer_version_permission(
        LayerName=layer["name"],
        VersionNumber=layer["version"],
        StatementId=statement_id,
        Action="lambda:GetLayerVersion",
        Principal=account_id,
    )
    ctx.on_cleanup(lambda: _remove_permission_ignore(lam, layer["name"], layer["version"], statement_id))
    readded_statement = json.loads(readded["Statement"])
    assert readded_statement["Sid"] == statement_id, (
        f"expected the freed StatementId to be reusable, got {readded_statement!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _layer_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/marker.txt", "sim2real behavioral layer content\n")
    return buf.getvalue()


def _publish_layer(ctx) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-layer-")
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

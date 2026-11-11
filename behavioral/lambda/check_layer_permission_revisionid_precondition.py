"""layer-permission-revisionid-precondition."""

from __future__ import annotations

import io
import json
import textwrap
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "layer-permission-revisionid-precondition"
GROUP = 'permissions'
SERVICES = ['lambda']

STALE_REVISION_MESSAGE = (
    "The Revision Id provided does not match the latest Revision Id. "
    "Call the GetLayerPolicy API to retrieve the latest Revision Id"
)


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _sids(lam, layer_name, version):
    policy = lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version)
    return {s["Sid"] for s in json.loads(policy["Policy"])["Statement"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddLayerVersionPermission/RemoveLayerVersionPermission reject a mismatched RevisionId."""
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-layer-")
    content = _make_zip("marker = 1\n", "python/marker.py")
    layer = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": content}, CompatibleRuntimes=["python3.12"]
    )
    version = layer["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))

    stmt_id = "sim2realbehavlayerrevlock"
    added = lam.add_layer_version_permission(
        LayerName=layer_name,
        VersionNumber=version,
        StatementId=stmt_id,
        Action="lambda:GetLayerVersion",
        Principal=_account_id(ctx),
    )
    rev1 = added["RevisionId"]

    stmt_id_2 = "sim2realbehavlayerrevlock2"
    stale_add_code, stale_add_msg = _error(
        lambda: lam.add_layer_version_permission(
            LayerName=layer_name,
            VersionNumber=version,
            StatementId=stmt_id_2,
            Action="lambda:GetLayerVersion",
            Principal=_account_id(ctx),
            RevisionId="00000000-0000-0000-0000-000000000000",
        )
    )
    assert stale_add_code == "PreconditionFailedException", (
        f"expected PreconditionFailedException, got {stale_add_code}"
    )
    assert stale_add_msg == STALE_REVISION_MESSAGE, f"unexpected message: {stale_add_msg!r}"
    sids_after_stale_add = _sids(lam, layer_name, version)
    assert sids_after_stale_add == {stmt_id}, (
        f"rejected AddLayerVersionPermission must not add a statement, got {sids_after_stale_add}"
    )

    added2 = lam.add_layer_version_permission(
        LayerName=layer_name,
        VersionNumber=version,
        StatementId=stmt_id_2,
        Action="lambda:GetLayerVersion",
        Principal=_account_id(ctx),
        RevisionId=rev1,
    )
    rev2 = added2["RevisionId"]
    assert rev2 != rev1, "RevisionId must advance after a successful AddLayerVersionPermission"
    sids_after_add = _sids(lam, layer_name, version)
    assert sids_after_add == {stmt_id, stmt_id_2}, (
        f"expected both statements present after the correctly-versioned add, got {sids_after_add}"
    )

    stale_remove_code, stale_remove_msg = _error(
        lambda: lam.remove_layer_version_permission(
            LayerName=layer_name, VersionNumber=version, StatementId=stmt_id, RevisionId=rev1
        )
    )
    assert stale_remove_code == "PreconditionFailedException", (
        f"expected PreconditionFailedException, got {stale_remove_code}"
    )
    assert stale_remove_msg == STALE_REVISION_MESSAGE, f"unexpected message: {stale_remove_msg!r}"
    sids_after_stale_remove = _sids(lam, layer_name, version)
    assert sids_after_stale_remove == {stmt_id, stmt_id_2}, (
        f"rejected RemoveLayerVersionPermission must not remove a statement, got {sids_after_stale_remove}"
    )

    lam.remove_layer_version_permission(
        LayerName=layer_name, VersionNumber=version, StatementId=stmt_id_2, RevisionId=rev2
    )
    sids_after_remove = _sids(lam, layer_name, version)
    assert sids_after_remove == {stmt_id}, (
        f"expected only the untouched statement left after the correctly-versioned remove, got {sids_after_remove}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

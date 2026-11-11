"""layer-permission-lifecycle."""

from __future__ import annotations

import io
import json
import textwrap
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "layer-permission-lifecycle"
GROUP = 'permissions'
SERVICES = ['lambda']


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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Layer version permission statement add/remove lifecycle and policy document state.

    Overly-permissive boundary: a duplicate StatementId on the same layer version is rejected.
    """
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-layer-")
    content = _make_zip("marker = 1\n", "python/marker.py")
    layer = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": content}, CompatibleRuntimes=["python3.12"]
    )
    version = layer["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))

    none_code, none_msg = _error(
        lambda: lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version)
    )
    assert none_code == "ResourceNotFoundException", f"expected no layer policy yet, got {none_code}"
    assert none_msg == "No policy is associated with the given resource.", f"unexpected message for a layer with no policy: {none_msg!r}"

    stmt_id = "sim2realbehavlayershare"
    added = lam.add_layer_version_permission(
        LayerName=layer_name,
        VersionNumber=version,
        StatementId=stmt_id,
        Action="lambda:GetLayerVersion",
        Principal=_account_id(ctx),
    )
    statement = json.loads(added["Statement"])
    assert statement["Sid"] == stmt_id, statement
    rev1 = added["RevisionId"]

    policy = lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version)
    doc = json.loads(policy["Policy"])
    assert any(s["Sid"] == stmt_id for s in doc["Statement"]), doc

    dup_code, dup_msg = _error(
        lambda: lam.add_layer_version_permission(
            LayerName=layer_name,
            VersionNumber=version,
            StatementId=stmt_id,
            Action="lambda:GetLayerVersion",
            Principal=_account_id(ctx),
        )
    )
    assert dup_code == "ResourceConflictException", f"expected ResourceConflictException, got {dup_code}"
    expected_dup = (
        f"The statement id ({stmt_id}) provided already exists. Please provide a new statement id, "
        f"or remove the existing statement."
    )
    assert dup_msg == expected_dup, f"expected message {expected_dup!r}, got {dup_msg!r}"

    policy_after_dup = lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version)
    doc_after_dup = json.loads(policy_after_dup["Policy"])
    assert [s["Sid"] for s in doc_after_dup["Statement"]] == [stmt_id], (
        f"rejected duplicate add must leave the policy untouched, got {doc_after_dup['Statement']}"
    )
    assert policy_after_dup["RevisionId"] == rev1, (
        f"rejected duplicate add must not advance RevisionId, expected {rev1}, "
        f"got {policy_after_dup['RevisionId']}"
    )

    lam.remove_layer_version_permission(
        LayerName=layer_name, VersionNumber=version, StatementId=stmt_id, RevisionId=rev1
    )
    gone_code, gone_msg = _error(
        lambda: lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version)
    )
    assert gone_code == "ResourceNotFoundException", f"expected layer policy gone, got {gone_code}"
    layer_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:layer:{layer_name}:{version}"
    expected_gone = f"Layer version {layer_arn} does not have any resource policy."
    assert gone_msg == expected_gone, f"expected message {expected_gone!r}, got {gone_msg!r}"

    remove_again_code, remove_again_msg = _error(
        lambda: lam.remove_layer_version_permission(
            LayerName=layer_name, VersionNumber=version, StatementId=stmt_id
        )
    )
    assert remove_again_code == "ResourceNotFoundException", (
        f"removing an already-removed statement must still report not-found, got {remove_again_code}"
    )
    assert remove_again_msg == "No policy is associated with the given resource.", (
        f"unexpected message removing an already-removed statement: {remove_again_msg!r}"
    )

    readded = lam.add_layer_version_permission(
        LayerName=layer_name,
        VersionNumber=version,
        StatementId=stmt_id,
        Action="lambda:GetLayerVersion",
        Principal=_account_id(ctx),
    )
    readded_statement = json.loads(readded["Statement"])
    assert readded_statement["Sid"] == stmt_id, (
        f"a removed StatementId must be reusable on the same layer version, got {readded_statement}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

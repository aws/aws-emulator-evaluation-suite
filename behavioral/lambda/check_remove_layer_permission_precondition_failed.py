"""remove-layer-permission-precondition-failed."""
from __future__ import annotations

import io
import json
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-layer-permission-precondition-failed"
GROUP = "concurrency"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveLayerVersionPermission with a stale RevisionId is PreconditionFailedException with the
    exact message and leaves both statements; with the current RevisionId the same call removes
    exactly that statement."""
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-layer-")
    publish = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _lambda_zip("# layer payload\n")},
        CompatibleRuntimes=["python3.12"],
    )
    version_number = publish["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version_number))

    # Real AWS validates that Principal be a genuine AWS account ID (or "*"/service
    # principal/org id) rather than an arbitrary well-formed 12-digit string, so use the
    # caller's own (always-valid) account ID for every grant. A layer version's resource
    # policy is keyed for uniqueness on StatementId, not Principal, so reusing the same
    # Principal on both statements is fine.
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    add1 = lam.add_layer_version_permission(
        LayerName=layer_name,
        VersionNumber=version_number,
        StatementId="stmt-a",
        Action="lambda:GetLayerVersion",
        Principal=account_id,
    )
    stale_revision = add1["RevisionId"]

    add2 = lam.add_layer_version_permission(
        LayerName=layer_name,
        VersionNumber=version_number,
        StatementId="stmt-b",
        Action="lambda:GetLayerVersion",
        Principal=account_id,
        RevisionId=stale_revision,
    )
    current_revision = add2["RevisionId"]
    assert current_revision != stale_revision, "revision id did not change after a successful update"

    code, code_msg = _error(
        lambda: lam.remove_layer_version_permission(
            LayerName=layer_name,
            VersionNumber=version_number,
            StatementId="stmt-a",
            RevisionId=stale_revision,
        )
    )
    assert code == "PreconditionFailedException", f"expected PreconditionFailedException, got {code!r}"
    assert code_msg == (
        "The Revision Id provided does not match the latest Revision Id. "
        "Call the GetLayerPolicy API to retrieve the latest Revision Id"
    ), (
        f"expected the exact 'PreconditionFailedException' message, got {code_msg!r}"
    )

    policy_after_reject = lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version_number)
    sids_after_reject = {s["Sid"] for s in json.loads(policy_after_reject["Policy"])["Statement"]}
    assert sids_after_reject == {"stmt-a", "stmt-b"}, (
        f"layer permission statements changed unexpectedly: {sids_after_reject}"
    )

    lam.remove_layer_version_permission(
        LayerName=layer_name,
        VersionNumber=version_number,
        StatementId="stmt-a",
        RevisionId=current_revision,
    )

    policy_after_restore = lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version_number)
    sids_after_restore = {s["Sid"] for s in json.loads(policy_after_restore["Policy"])["Statement"]}
    assert sids_after_restore == {"stmt-b"}, (
        f"identical remove with the current RevisionId did not remove stmt-a: {sids_after_restore}"
    )


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _lambda_zip(handler_body: str = "def handler(event, context):\n    return {'ok': True}\n") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_body)
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

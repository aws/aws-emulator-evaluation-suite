"""add-layer-version-permission-organization-id-requires-wildcard-principal-rejected."""
from __future__ import annotations

import io
import json
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-layer-version-permission-organization-id-requires-wildcard-principal-rejected"
GROUP = "layers"
SERVICES = ["lambda"]

_ORG_ID = "o-sim2realbeh01"


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/marker.txt", "sim2real behavioral layer content\n")
    return buf.getvalue()


def _client_error(fn):
    """(code, message) of a call that must be refused; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _sids(lam, layer_name: str, version: int) -> set:
    doc = json.loads(lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version)["Policy"])
    return {s["Sid"] for s in doc["Statement"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddLayerVersionPermission rejects an OrganizationId paired with a specific-account
    Principal with InvalidParameterValueException; the same OrganizationId with Principal "*"
    is granted."""
    lam = ctx.client("lambda")
    account = ctx.account
    layer_name = ctx.unique_name("sim2real-behav-layer-")

    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _zip_bytes()},
        CompatibleRuntimes=["python3.12"],
    )
    version = published["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))

    # Positive control: a specific-account grant with no OrganizationId succeeds.
    account_grant = lam.add_layer_version_permission(
        LayerName=layer_name,
        VersionNumber=version,
        StatementId="sim2real-account-grant",
        Action="lambda:GetLayerVersion",
        Principal=account,
    )
    assert json.loads(account_grant["Statement"])["Sid"] == "sim2real-account-grant", (
        f"expected the account grant to be recorded, got {account_grant!r}"
    )

    # Break exactly one thing: pair that same specific-account Principal with an OrganizationId.
    code, message = _client_error(
        lambda: lam.add_layer_version_permission(
            LayerName=layer_name,
            VersionNumber=version,
            StatementId="sim2real-orgid-mismatch",
            Action="lambda:GetLayerVersion",
            Principal=account,
            OrganizationId=_ORG_ID,
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for an OrganizationId paired with a "
        f"specific-account Principal, got {code!r}"
    )
    expected_message = "If organization id is specified then principal should be *"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    sids_after_reject = _sids(lam, layer_name, version)
    assert "sim2real-orgid-mismatch" not in sids_after_reject, (
        f"the rejected statement must not appear in the policy, got {sids_after_reject!r}"
    )
    assert "sim2real-account-grant" in sids_after_reject, (
        f"the earlier successful grant must still be present, got {sids_after_reject!r}"
    )

    # The legal neighbour: the identical OrganizationId value, with Principal "*", is granted.
    org_grant = lam.add_layer_version_permission(
        LayerName=layer_name,
        VersionNumber=version,
        StatementId="sim2real-org-grant",
        Action="lambda:GetLayerVersion",
        Principal="*",
        OrganizationId=_ORG_ID,
    )
    assert json.loads(org_grant["Statement"])["Sid"] == "sim2real-org-grant", (
        f"expected the organization grant to be recorded, got {org_grant!r}"
    )

    sids_after_neighbour = _sids(lam, layer_name, version)
    assert "sim2real-org-grant" in sids_after_neighbour, (
        f"the organization grant must be present, got {sids_after_neighbour!r}"
    )
    assert "sim2real-orgid-mismatch" not in sids_after_neighbour, (
        f"the earlier rejected statement must still be absent, got {sids_after_neighbour!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

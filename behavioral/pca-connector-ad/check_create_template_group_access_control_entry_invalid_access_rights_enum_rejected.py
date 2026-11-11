"""create-template-group-access-control-entry-invalid-access-rights-enum-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-template-group-access-control-entry-invalid-access-rights-enum-rejected"
GROUP = "validation"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTemplateGroupAccessControlEntry rejects an AccessRights.Enroll value outside ALLOW|DENY
    with ValidationException and its exact message, while a valid value on the same nonexistent
    TemplateArn gets the exact Template ResourceNotFoundException."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]
    template_arn = (
        f"arn:aws:pca-connector-ad:{ctx.region}:{account}:connector/"
        f"{uuid.uuid4()}/template/{uuid.uuid4()}"
    )
    sid = "S-1-5-21-1004336348-1177238915-682003330-1401"

    code, message = _error_code(
        lambda: pcad.create_template_group_access_control_entry(
            TemplateArn=template_arn,
            GroupSecurityIdentifier=sid,
            GroupDisplayName="sim2real-group",
            AccessRights={"Enroll": "MAYBE", "AutoEnroll": "DENY"},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an out-of-enum AccessRights.Enroll value, got {code!r}"
    )
    assert message == (
        '[instance value ("MAYBE") not found in enum (possible values: ["ALLOW","DENY"])]'
    ), message

    control_code, control_message = _error_code(
        lambda: pcad.create_template_group_access_control_entry(
            TemplateArn=template_arn,
            GroupSecurityIdentifier=sid,
            GroupDisplayName="sim2real-group",
            AccessRights={"Enroll": "ALLOW", "AutoEnroll": "DENY"},
        )
    )
    assert control_code == "ResourceNotFoundException", (
        "expected ResourceNotFoundException for a valid enum against the same nonexistent "
        f"TemplateArn (proves the enum check, not a broken call path, caused the first "
        f"rejection), got {control_code!r}"
    )
    assert control_message == f"Template was not found: {template_arn}.", control_message


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

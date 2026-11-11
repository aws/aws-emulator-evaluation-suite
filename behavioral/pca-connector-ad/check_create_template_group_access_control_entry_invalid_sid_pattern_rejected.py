"""create-template-group-access-control-entry-invalid-sid-pattern-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-template-group-access-control-entry-invalid-sid-pattern-rejected"
GROUP = "validation"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTemplateGroupAccessControlEntry rejects a GroupSecurityIdentifier that fails its SID
    pattern with ValidationException and its exact message, while a well-formed SID on the same
    nonexistent TemplateArn gets the exact Template ResourceNotFoundException."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]
    template_arn = (
        f"arn:aws:pca-connector-ad:{ctx.region}:{account}:connector/"
        f"{uuid.uuid4()}/template/{uuid.uuid4()}"
    )
    valid_sid = "S-1-5-21-1004336348-1177238915-682003330-1401"

    code, message = _error_code(
        lambda: pcad.create_template_group_access_control_entry(
            TemplateArn=template_arn,
            GroupSecurityIdentifier="not-a-valid-sid",
            GroupDisplayName="sim2real-group",
            AccessRights={"Enroll": "ALLOW", "AutoEnroll": "DENY"},
        )
    )
    assert code == "ValidationException"
    assert message == (
        '[ECMA 262 regex "^S-[0-9]-([0-9]+-){1,14}[0-9]+$" does not match input string '
        '"not-a-valid-sid"]'
    ), message

    control_code, control_message = _error_code(
        lambda: pcad.create_template_group_access_control_entry(
            TemplateArn=template_arn,
            GroupSecurityIdentifier=valid_sid,
            GroupDisplayName="sim2real-group",
            AccessRights={"Enroll": "ALLOW", "AutoEnroll": "DENY"},
        )
    )
    assert control_code == "ResourceNotFoundException"
    assert control_message == f"Template was not found: {template_arn}.", control_message


def _error_code(fn):
    """Call fn(); return its error (code, message). A success raises, because a target that
    accepts what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""get-role-template-version."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-role-template-version"
GROUP = 'role_lifecycle'
SERVICES = ['iam']

# An AWS-owned, permanent role template -- analogous to an AWS managed policy, whose ARN lives
# under the "aws" pseudo-account rather than any caller's. There is no public list/discovery
# operation for role templates, but this one is a stable literal: real AWS resolves it with a 200
# and the same TemplateName/ManagedPolicyArns every time, which is what makes it usable as the
# positive control below.
KNOWN_TEMPLATE_ARN = "arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRoleTemplateVersion returns PowerUserRoleTemplate (with PowerUserAccess) for its AWS-owned
    ARN, rejects a TemplateArn of valid length but not ARN-shaped with the exact ValidationError,
    and a well-formed unknown ARN in the "aws" namespace with the exact NoSuchEntity."""
    iam = ctx.client("iam")
    if not hasattr(iam, "get_role_template_version"):
        raise AssertionError("get_role_template_version not available in the installed botocore")

    template = iam.get_role_template_version(TemplateArn=KNOWN_TEMPLATE_ARN)["RoleTemplateVersion"]
    assert template.get("TemplateName") == "PowerUserRoleTemplate", (
        f"expected TemplateName PowerUserRoleTemplate, got {template.get('TemplateName')}"
    )
    assert template.get("TemplateArn") == KNOWN_TEMPLATE_ARN, (
        f"expected TemplateArn to echo the request, got {template.get('TemplateArn')}"
    )
    assert "arn:aws:iam::aws:policy/PowerUserAccess" in template.get("ManagedPolicyArns", []), (
        f"expected PowerUserAccess in ManagedPolicyArns, got {template.get('ManagedPolicyArns')}"
    )

    # Must clear the client-side minimum length (botocore raises ParamValidationError below that,
    # before any request is sent) while still being nowhere close to a valid ARN shape.
    malformed_arn = "not-a-valid-arn-shape-at-all"
    code_short, message = _error(lambda: iam.get_role_template_version(TemplateArn=malformed_arn))
    assert code_short == "ValidationError", (
        f"expected ValidationError for a malformed TemplateArn, got {code_short}"
    )
    expected = "Invalid ARN:  Could not be parsed!"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    fake_arn = f"arn:aws:iam::aws:role-template/sim2real/{ctx.unique_name('tmpl-')}:1"
    code, message = _error(lambda: iam.get_role_template_version(TemplateArn=fake_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent TemplateArn, got {code}"
    expected = f"Role Template {fake_arn} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

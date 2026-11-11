"""get-role-template-version-contract."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-role-template-version-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]

# PowerUserRoleTemplate is a permanent, AWS-owned role template that exists identically in every
# account (its ARN uses the "aws" pseudo-account, like an AWS managed policy). It is the positive
# control: without a real success path, "rejects a malformed TemplateArn" is indistinguishable from
# "rejects every GetRoleTemplateVersion call".
_REAL_TEMPLATE_ARN = (
    "arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRoleTemplateVersion returns PowerUserRoleTemplate for its AWS-owned ARN, rejects a
    TemplateArn built with the caller's account id with the exact ValidationError (role templates
    live in the "aws" namespace) and an unknown "aws"-namespace ARN with the exact NoSuchEntity."""

    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control.
    version = iam.get_role_template_version(TemplateArn=_REAL_TEMPLATE_ARN)[
        "RoleTemplateVersion"
    ]
    assert version["TemplateArn"] == _REAL_TEMPLATE_ARN, (
        f"expected TemplateArn to echo {_REAL_TEMPLATE_ARN}, got {version.get('TemplateArn')}"
    )
    assert version["TemplateName"] == "PowerUserRoleTemplate", (
        f"expected TemplateName PowerUserRoleTemplate, got {version.get('TemplateName')}"
    )

    # Error boundary 1: TemplateArn carries the caller's own account id, not the "aws" pseudo-account.
    bogus_arn = (
        f"arn:aws:iam::{account_id}:role-template/does-not-exist/sim2real-example:1"
    )
    code, message = _error(lambda: iam.get_role_template_version(TemplateArn=bogus_arn))
    assert code == "ValidationError", (
        f"expected ValidationError for malformed TemplateArn, got {code}"
    )
    expected = (
        "The specified role template ARN is not valid. The ARN must use 'aws' as the account "
        "field (e.g., arn:aws:iam::aws:role-template/...)."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Error boundary 2: TemplateArn is well-formed and in the reserved "aws" namespace, but names no
    # real template.
    fake_arn = f"arn:aws:iam::aws:role-template/iam.amazonaws.com/{ctx.unique_name('sim2real-tmpl-')}:1"
    code, message = _error(lambda: iam.get_role_template_version(TemplateArn=fake_arn))
    assert code == "NoSuchEntity", (
        f"expected NoSuchEntity for a nonexistent TemplateArn, got {code}"
    )
    expected = f"Role Template {fake_arn} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

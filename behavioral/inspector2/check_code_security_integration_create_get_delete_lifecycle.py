"""code-security-integration-create-get-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "code-security-integration-create-get-delete-lifecycle"
GROUP = "error-semantics"
SERVICES = ["inspector2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCodeSecurityIntegration in an account without Code Security enabled fails with
    AccessDeniedException "Invoking account is not Code Security enabled." and no integration is
    listed."""
    inspector2 = ctx.client("inspector2")
    name = ctx.unique_name("sim2real-codesec-")

    code, msg = _error_code(lambda: inspector2.create_code_security_integration(name=name, type="GITHUB"))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert msg == "Invoking account is not Code Security enabled.", msg

    # Effect absent: no integration with this name was created.
    names = {i["name"] for i in _all_integrations(inspector2)}
    assert name not in names, "an integration was created despite the account not being Code Security enabled"

    # Positive control: Code Security read APIs are otherwise fully functional for this caller.
    resp = inspector2.list_code_security_integrations()
    assert "integrations" in resp, f"expected a well-formed list response, got {resp!r}"


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _all_integrations(inspector2):
    items = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_code_security_integrations(**kwargs)
        items.extend(resp.get("integrations", []))
        next_token = resp.get("nextToken")
        if not next_token:
            return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


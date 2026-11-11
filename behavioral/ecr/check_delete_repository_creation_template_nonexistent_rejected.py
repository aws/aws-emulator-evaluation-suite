"""delete-repository-creation-template-nonexistent-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-repository-creation-template-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRepositoryCreationTemplate for a prefix with no template returns
    TemplateNotFoundException, while a template that WAS created deletes successfully
    exactly once and cannot be deleted a second time."""
    ecr = ctx.client("ecr")
    prefix = _ecr_name(ctx, "sim2realtmpl")

    # Sanity: no template exists yet for this fresh, never-used prefix.
    err, err_msg = _error(lambda: ecr.delete_repository_creation_template(prefix=prefix))
    assert err == "TemplateNotFoundException", f"expected TemplateNotFoundException, got {err}"
    expected_msg = f"A repository creation template with prefix '{prefix}' is not found in the registry with id '{ctx.account}'"
    assert err_msg == expected_msg, f"expected message {expected_msg!r}, got {err_msg!r}"

    # Positive control: create one, confirm it is listed, then delete it successfully.
    ecr.create_repository_creation_template(prefix=prefix, appliedFor=["PULL_THROUGH_CACHE"])
    ctx.on_cleanup(lambda: _safe_delete_template(ecr, prefix))

    created_prefixes = {
        t["prefix"] for t in ecr.describe_repository_creation_templates()["repositoryCreationTemplates"]
    }
    assert prefix in created_prefixes, f"expected {prefix!r} listed after create, saw {created_prefixes!r}"

    ecr.delete_repository_creation_template(prefix=prefix)
    remaining_prefixes = {
        t["prefix"] for t in ecr.describe_repository_creation_templates()["repositoryCreationTemplates"]
    }
    assert prefix not in remaining_prefixes, f"expected {prefix!r} gone after delete, still saw it in {remaining_prefixes!r}"

    # Deleting the same, now-gone template a second time is rejected, not a silent no-op.
    err2, err2_msg = _error(lambda: ecr.delete_repository_creation_template(prefix=prefix))
    assert err2 == "TemplateNotFoundException", f"expected TemplateNotFoundException on re-delete, got {err2}"
    expected_msg = f"A repository creation template with prefix '{prefix}' is not found in the registry with id '{ctx.account}'"
    assert err2_msg == expected_msg, f"expected message {expected_msg!r}, got {err2_msg!r}"


def _ecr_name(ctx, base: str, max_len: int = 30) -> str:
    raw = ctx.unique_name(base).lower()
    raw = re.sub(r"[^a-z0-9\-]", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    return raw[:max_len]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_template(ecr, prefix):
    try:
        ecr.delete_repository_creation_template(prefix=prefix)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TemplateNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

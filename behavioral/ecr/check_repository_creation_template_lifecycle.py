"""repository-creation-template-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")

CHECK = "repository-creation-template-lifecycle"
GROUP = 'repository-creation-template'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRepositoryCreationTemplate -> Describe -> Update -> Delete round-trips the
    template and leaves it absent afterwards: an independent list no longer shows it, and
    Update on the deleted prefix fails with TemplateNotFoundException."""
    ecr = ctx.client("ecr")
    prefix = ctx.unique_name("rct-")
    ecr.create_repository_creation_template(
        prefix=prefix,
        appliedFor=["PULL_THROUGH_CACHE"],
        imageTagMutability="MUTABLE",
        resourceTags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda _p=prefix: _delete_template(ecr, _p))

    desc = ecr.describe_repository_creation_templates(prefixes=[prefix])
    templates = desc["repositoryCreationTemplates"]
    assert len(templates) == 1, f"expected exactly 1 template for prefix {prefix!r}, got {len(templates)}"
    assert templates[0]["imageTagMutability"] == "MUTABLE", (
        f"expected MUTABLE right after creation, got {templates[0]['imageTagMutability']!r}"
    )

    ecr.update_repository_creation_template(prefix=prefix, imageTagMutability="IMMUTABLE")
    desc2 = ecr.describe_repository_creation_templates(prefixes=[prefix])
    templates2 = desc2["repositoryCreationTemplates"]
    assert templates2[0]["imageTagMutability"] == "IMMUTABLE", (
        f"expected IMMUTABLE after update, got {templates2[0]['imageTagMutability']!r}"
    )

    ecr.delete_repository_creation_template(prefix=prefix)

    remaining = {
        t["prefix"] for t in ecr.describe_repository_creation_templates()["repositoryCreationTemplates"]
    }
    assert prefix not in remaining, f"deleted template {prefix!r} is still listed by an independent read"

    code, message = _client_error(
        lambda: ecr.update_repository_creation_template(
            prefix=prefix, imageTagMutability="MUTABLE"
        )
    )
    assert code == "TemplateNotFoundException", (
        f"expected TemplateNotFoundException updating a deleted template, got {code!r}"
    )
    assert message == (
        f"A repository creation template with prefix '{prefix}' is not found in the registry "
        f"with id '{ctx.account}'"
    ), message


def _delete_template(ecr, prefix):
    """Teardown: a template the check already deleted is not an error."""
    try:
        ecr.delete_repository_creation_template(prefix=prefix)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TemplateNotFoundException":
            raise

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""describe-registries-alias-record-is-fully-populated."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "describe-registries-alias-record-is-fully-populated"
GROUP = 'registry'
SERVICES = ['ecr-public']

_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
# com.amazonaws.ecrpublic#RegistryAliasName
_ALIAS_RE = re.compile(r"^[a-z][a-z0-9]+(?:[._-][a-z0-9]+)*$")
# Registry has FIVE @required members; RegistryAlias has four (two with @default false).
_REGISTRY_REQUIRED = {"registryId", "registryArn", "registryUri", "verified", "aliases"}
_ALIAS_REQUIRED = {"name", "status", "primaryRegistryAlias", "defaultRegistryAlias"}
_ALIAS_STATUSES = {"ACTIVE", "PENDING", "REJECTED"}


def _public_ecr_host(host: str) -> bool:
    """``public.ecr.<domain>``: the ECR Public service labels lead, then the target's own domain."""
    labels = host.split(".")
    return labels[:2] == ["public", "ecr"] and len(labels) > 2 and all(labels[2:])


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRegistries returns one registry with every @required member, exactly one primary
    alias, and a registryUri/registryArn that agree with that alias and the account id.
    """
    ecr = ctx.client("ecr-public")

    # The alias is provisioned lazily on the account's first CreateRepository; an untouched
    # account answers aliases: [] and registryUri: ''.
    name, created = _create_repository(ctx, ecr)

    registries = ecr.describe_registries()["registries"]
    assert registries, "DescribeRegistries must return the account's registry, not an empty list"
    assert len(registries) == 1, f"an account has exactly one public registry, got {registries}"
    registry = registries[0]

    missing = _REGISTRY_REQUIRED - set(registry)
    assert not missing, f"Registry is missing @required members {sorted(missing)}: {registry}"

    account = registry["registryId"]
    assert _ACCOUNT_RE.match(account), f"registryId must be a 12-digit account id, got {account!r}"
    assert registry["registryArn"] == f"arn:aws:ecr-public::{account}:registry/{account}", (
        registry["registryArn"]
    )
    assert isinstance(registry["verified"], bool), (
        f"verified is a boolean, got {type(registry['verified']).__name__}: {registry['verified']!r}"
    )

    aliases = registry["aliases"]
    assert aliases, (
        f"a registry carries at least one alias once its account has a repository, got {aliases}"
    )
    for a in aliases:
        amissing = _ALIAS_REQUIRED - set(a)
        assert not amissing, f"RegistryAlias is missing {sorted(amissing)}: {a}"
        assert _ALIAS_RE.match(a["name"]), f"alias name violates RegistryAliasName: {a['name']!r}"
        assert 2 <= len(a["name"]) <= 50, f"alias name length out of 2..50: {a['name']!r}"
        assert a["status"] in _ALIAS_STATUSES, f"unknown alias status {a['status']!r}"
        assert isinstance(a["primaryRegistryAlias"], bool), a
        assert isinstance(a["defaultRegistryAlias"], bool), a

    primary = [a for a in aliases if a["primaryRegistryAlias"]]
    assert len(primary) == 1, f"exactly one alias must be primary, got {primary} of {aliases}"
    assert primary[0]["status"] == "ACTIVE", (
        f"the primary alias must be ACTIVE, got {primary[0]['status']!r}"
    )
    alias = primary[0]["name"]
    # registryUri is public.ecr.<domain>/<alias>; the domain is the target's own.
    host, _, path = registry["registryUri"].partition("/")
    assert _public_ecr_host(host) and path == alias, (registry["registryUri"], alias)

    # The alias is stable account state, not per-request: a second call must agree exactly.
    again = ecr.describe_registries()["registries"]
    assert again == registries, f"DescribeRegistries is not stable across calls: {registries} vs {again}"

    # The alias must be the one baked into the repository's repositoryUri.
    uri = created["repository"]["repositoryUri"]
    assert uri == f"{registry['registryUri']}/{name}", (
        f"repositoryUri must be registryUri + '/' + name; registryUri={registry['registryUri']!r} "
        f"name={name!r} uri={uri!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""server-side-repository-uri-server-assigned."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "server-side-repository-uri-server-assigned"
GROUP = "server-side"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRepository always returns a server-assigned public.ecr.<domain>/<alias>/<name> repositoryUri that
    the client has no input field to influence, and it stays stable across describes."""
    ecrpublic = _ecrpublic(ctx)
    name = ctx.unique_name("sim2real-behav-ecrpub-uri-")
    created = ecrpublic.create_repository(repositoryName=name)["repository"]
    ctx.on_cleanup(lambda: ecrpublic.delete_repository(repositoryName=name, force=True))

    uri = created["repositoryUri"]
    # CreateRepository's request shape has no "repositoryUri" input member at all (only
    # repositoryName/catalogData/tags/registryId) -- the server derives it entirely, and it
    # must be built from the account's registry alias plus the exact repository name.
    host, _, path = uri.partition("/")
    assert _public_ecr_host(host), f"expected a public.ecr.<domain> host before the path, got {uri!r}"
    assert path.endswith(f"/{name}"), f"expected uri ending in /{name}, got {uri!r}"

    registry = ecrpublic.describe_registries()["registries"][0]
    # aliases[0] is not necessarily the primary one -- an account can carry more than one
    # alias, and only the entry flagged primaryRegistryAlias is the one CreateRepository used.
    primary = [a for a in registry["aliases"] if a.get("primaryRegistryAlias")]
    assert len(primary) == 1, f"expected exactly one primaryRegistryAlias, got {registry['aliases']!r}"
    alias = primary[0]["name"]
    assert path == f"{alias}/{name}", f"expected uri public.ecr.<domain>/{alias}/{name}, got {uri!r}"

    described = ecrpublic.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described["repositoryUri"] == uri, (
        f"describe repositoryUri {described['repositoryUri']!r} != create-time uri {uri!r}"
    )
    assert described["repositoryArn"] == created["repositoryArn"], (
        f"describe repositoryArn {described['repositoryArn']!r} != "
        f"create-time arn {created['repositoryArn']!r}"
    )
    assert described["registryId"] == created["registryId"], (
        f"describe registryId {described['registryId']!r} != create-time {created['registryId']!r}"
    )

    # Stable across a second describe call too -- not regenerated per-request.
    described_again = ecrpublic.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described_again["repositoryUri"] == uri, (
        f"repositoryUri changed across describes: {described_again['repositoryUri']!r} != {uri!r}"
    )


def _public_ecr_host(host: str) -> bool:
    """``public.ecr.<domain>``: the ECR Public service labels lead, then the target's own domain."""
    labels = host.split(".")
    return labels[:2] == ["public", "ecr"] and len(labels) > 2 and all(labels[2:])


def _ecrpublic(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so pin that region on the
    target ctx names."""
    from botocore.config import Config

    return ctx.client("ecr-public", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"}))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

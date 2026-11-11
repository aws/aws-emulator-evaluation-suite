"""repository-uri-and-arn-are-alias-scoped-and-regionless."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "repository-uri-and-arn-are-alias-scoped-and-regionless"
GROUP = 'registry'
SERVICES = ['ecr-public']

# ECR Public is a single global registry per account addressed by a public alias. Both facts
# show up in the shapes the API mints, and neither has a private-ECR analogue:
#   public : repositoryUri = public.ecr.<domain>/<alias>/<name>   (no account, no region)
#            repositoryArn = arn:aws:ecr-public::<acct>:repository/<name>   (EMPTY region field)
#   private: repositoryUri = <acct>.dkr.ecr.<region>.<domain>/<name>
#            repositoryArn = arn:aws:ecr:<region>:<acct>:repository/<name>
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
# com.amazonaws.ecrpublic#RegistryAliasName
_ALIAS_RE = re.compile(r"^[a-z][a-z0-9]+(?:[._-][a-z0-9]+)*$")


def _public_ecr_host(host: str) -> bool:
    """``public.ecr.<domain>``: the ECR Public service labels lead, then the target's own domain."""
    labels = host.split(".")
    return labels[:2] == ["public", "ecr"] and len(labels) > 2 and all(labels[2:])


def _err(fn):
    """Call fn(), which must fail; return the ClientError's (Code, Message). A success raises."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected the call to fail with a ClientError, but it succeeded")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)

    def _delete():
        # The body deletes the nested repository itself; a repository already gone is clean.
        try:
            ecr.delete_repository(repositoryName=name, force=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
                raise

    ctx.on_cleanup(_delete)
    return name, resp


def _primary_alias(registry) -> str:
    """The account's primary public registry alias, from a DescribeRegistries record."""
    primary = [a for a in registry["aliases"] if a.get("primaryRegistryAlias")]
    assert len(primary) == 1, f"expected exactly one primaryRegistryAlias, got {registry['aliases']}"
    return primary[0]["name"]


def _assert_repository_shape(repo, *, name, account, alias, region):
    """Every identity field ECR Public mints for a repository, asserted exactly; the URI's host by
    the labels it must not carry, since its domain is the environment's."""
    assert repo["repositoryName"] == name, repo
    assert repo["registryId"] == account, (repo["registryId"], account)

    uri = repo["repositoryUri"]
    host, _, path = uri.partition("/")
    assert _public_ecr_host(host) and path == f"{alias}/{name}", uri
    # An emulator that reuses private ECR's URI builder produces the <acct>.dkr.ecr.<region> host;
    # a region-scoped emulator leaks the region in. Neither label may appear.
    labels = host.split(".")
    assert "dkr" not in labels and account not in labels and region not in labels, uri

    arn = repo["repositoryArn"]
    assert arn == f"arn:aws:ecr-public::{account}:repository/{name}", arn
    parts = arn.split(":", 5)
    assert parts[2] == "ecr-public", parts
    # The region field of an ecr-public ARN is EMPTY — the registry is global.
    assert parts[3] == "", f"ecr-public ARNs carry no region, got {parts[3]!r} in {arn}"
    assert parts[4] == account, parts


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A public repository's repositoryUri is public.ecr.<domain>/<alias>/<name> and its ARN has an
    empty region field, for flat and slash-nested names, across Create/Describe/DeleteRepository.
    """
    ecr = ctx.client("ecr-public")
    region = ecr.meta.region_name

    # The account's registry alias is lazily provisioned: on an account that has never used
    # ECR Public, DescribeRegistries returns `aliases: []` until the first CreateRepository mints
    # one, so the repository is created before the alias is read.
    flat, created = _create_repository(ctx, ecr)

    registries = ecr.describe_registries()["registries"]
    assert len(registries) == 1, f"an account has exactly one public registry, got {registries}"
    registry = registries[0]
    account = registry["registryId"]
    assert _ACCOUNT_RE.match(account), f"registryId must be a 12-digit account id, got {account!r}"
    alias = _primary_alias(registry)
    assert _ALIAS_RE.match(alias) and 2 <= len(alias) <= 50, f"bad registry alias {alias!r}"

    _assert_repository_shape(
        created["repository"], name=flat, account=account, alias=alias, region=region
    )

    described = ecr.describe_repositories(repositoryNames=[flat])["repositories"]
    assert len(described) == 1, described
    _assert_repository_shape(
        described[0], name=flat, account=account, alias=alias, region=region
    )

    # --- slash-nested name (RepositoryName pattern allows `a/b/c`) --------------------
    nested_name = f"{ctx.unique_name('sim2real-behav-ecrpub-ns-')}/team/app"
    nested, created_nested = _create_repository(ctx, ecr, name=nested_name)
    _assert_repository_shape(
        created_nested["repository"], name=nested, account=account, alias=alias, region=region
    )
    assert created_nested["repository"]["repositoryUri"].count("/") == 4, (
        "public.ecr.<domain>/<alias>/a/b/c has four slashes; the nested path must survive verbatim: "
        f"{created_nested['repository']['repositoryUri']}"
    )

    described_nested = ecr.describe_repositories(repositoryNames=[nested])["repositories"]
    assert len(described_nested) == 1, described_nested
    assert described_nested[0]["repositoryName"] == nested, described_nested[0]

    # The nested-name ARN must be usable as a tagging target — `/` in the resource segment
    # is where hand-rolled ARN parsers break.
    nested_arn = created_nested["repository"]["repositoryArn"]
    ecr.tag_resource(
        resourceArn=nested_arn, tags=[{"Key": "sim2real-nested", "Value": "synthetic"}]
    )
    listed = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=nested_arn)["tags"]}
    assert listed.get("sim2real-nested") == "synthetic", listed

    # --- delete echoes the same identity fields --------------------------------------
    deleted = ecr.delete_repository(repositoryName=nested, force=True)
    _assert_repository_shape(deleted["repository"], name=nested, account=account, alias=alias, region=region)
    code, message = _err(lambda: ecr.describe_repositories(repositoryNames=[nested]))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert message == (
        f"The repository with name '{nested}' does not exist in the registry with id '{account}'"
    ), f"DescribeRepositories message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

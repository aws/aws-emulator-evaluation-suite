"""create-repository-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-repository-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected ConflictException, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRepository rejects a name already used within the same domain with
    ConflictException, and the original repository's metadata is left unchanged."""
    ca = ctx.client("codeartifact")
    domain = (ctx.unique_name("sim2real-ca-") + "0").lower()
    repo = ctx.unique_name("sim2real-ca-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    first = ca.create_repository(
        domain=domain, repository=repo, description="original",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["repository"]
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    refusal = _error(
        lambda: ca.create_repository(domain=domain, repository=repo, description="duplicate-attempt")
    )
    expected = ("ConflictException", f"Repository {repo} already exists in domain {domain}.")
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Effect absent: the original repository's description was not overwritten.
    described = ca.describe_repository(domain=domain, repository=repo)["repository"]
    assert described["description"] == "original", (
        f"expected the original description 'original' to survive the rejected duplicate create, "
        f"got {described['description']!r}"
    )
    assert described["arn"] == first["arn"], (
        f"expected the original repository's arn {first['arn']!r} unchanged, got {described['arn']!r}"
    )

    # Positive control: a repository with a different name in the same domain succeeds.
    other_repo = ctx.unique_name("sim2real-ca-repo-")
    other = ca.create_repository(
        domain=domain, repository=other_repo, tags=[{"key": "sim2real", "value": CHECK}]
    )["repository"]
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=other_repo))
    assert other["name"] == other_repo, f"expected positive-control repo named {other_repo!r}, got {other['name']!r}"

    # Terminal read: independent of the create call above, at the destination.
    other_described = ca.describe_repository(domain=domain, repository=other_repo)["repository"]
    assert other_described["name"] == other_repo and other_described["arn"] == other["arn"], (
        f"independent read of the positive-control repository returned {other_described!r}, "
        f"expected name={other_repo!r} arn={other['arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

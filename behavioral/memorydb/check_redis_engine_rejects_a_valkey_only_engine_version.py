"""redis-engine-rejects-a-valkey-only-engine-version."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redis-engine-rejects-a-valkey-only-engine-version"
GROUP = "engine-identity"
SERVICES = ["memorydb"]

#: Valkey's catalogue starts here; the Redis OSS lineage MemoryDB offers tops out at 7.1 (the
#: AWS MemoryDB Developer Guide's engine-versions page: Valkey 7.2.6 is a fork of Redis OSS
#: 7.2.4, and MemoryDB never offered a 7.2+ Redis OSS version).
_VALKEY_ONLY_VERSION = "7.2"


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster(Engine="redis", EngineVersion="7.2") is refused, while DescribeEngineVersions
    lists 7.2 for valkey and, for redis, lists 7.1 but never 7.2: the refusal tracks the catalogue.
    """
    mdb = ctx.client("memorydb")
    name = ctx.unique_name("sim2real-mdbver-")
    ctx.on_cleanup(lambda: _drop_if_created(mdb, name))

    valkey = _versions(mdb, "valkey")
    assert _VALKEY_ONLY_VERSION in valkey, (
        f"valkey's catalogue {sorted(valkey)!r} does not offer {_VALKEY_ONLY_VERSION!r}"
    )
    offered = _versions(mdb, "redis")
    assert "7.1" in offered, f"redis's catalogue {sorted(offered)!r} lacks a usable 7.1"
    assert _VALKEY_ONLY_VERSION not in offered, (
        f"redis's catalogue {sorted(offered)!r} unexpectedly offers the Valkey-only "
        f"{_VALKEY_ONLY_VERSION!r}"
    )

    got = _error(
        lambda: mdb.create_cluster(
            ClusterName=name,
            NodeType="db.t4g.small",
            Engine="redis",
            EngineVersion=_VALKEY_ONLY_VERSION,
            ACLName="open-access",
        )
    )
    want = (
        "InvalidParameterCombinationException",
        f"Invalid engine version {_VALKEY_ONLY_VERSION} specified for the cluster",
    )
    assert got == want, f"Engine=redis EngineVersion={_VALKEY_ONLY_VERSION!r} raised {got!r}, expected {want!r}"

    got = _error(lambda: mdb.describe_clusters(ClusterName=name))
    want = ("ClusterNotFoundFault", f"Cluster {name} not found.")
    assert got == want, f"a refused cluster describes as {got!r}, expected {want!r}"


def _versions(mdb, engine: str) -> set[str]:
    """Every EngineVersion DescribeEngineVersions lists for ``engine``, across all pages."""
    out, token = set(), None
    while True:
        page = mdb.describe_engine_versions(Engine=engine, **({"NextToken": token} if token else {}))
        out |= {v["EngineVersion"] for v in page["EngineVersions"]}
        token = page.get("NextToken")
        if not token:
            return out


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) ``fn()`` raises; raises itself when the call SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call succeeded; real AWS rejects it. It returned {result!r}")


def _drop_if_created(mdb, name: str) -> None:
    """Net for a cluster this check's negative probe might unexpectedly have created."""
    try:
        mdb.delete_cluster(ClusterName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ClusterNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

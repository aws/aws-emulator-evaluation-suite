"""engine-default-parameters-change-type-and-family-divergence."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "engine-default-parameters-change-type-and-family-divergence"
GROUP = 'discovery'
SERVICES = ['elasticache']

# ChangeType is a modeled enum on the Parameter shape: exactly these two values.
_CHANGE_TYPES = {"immediate", "requires-reboot"}
_RANGE_RE = re.compile(r"^\d+-\d*$")


def _error_code(fn):
    """Call fn() and return the botocore Error.Code; raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _engine_defaults(ec, family):
    """Every default Parameter for `family`, following the Marker pagination to the end.

    Returns (params_by_name, page_count, first_page_names).
    """
    by_name = {}
    marker = None
    pages = 0
    first_page = []
    while True:
        kwargs = {"CacheParameterGroupFamily": family, "MaxRecords": 20}
        if marker:
            kwargs["Marker"] = marker
        defaults = ec.describe_engine_default_parameters(**kwargs)["EngineDefaults"]
        pages += 1
        names = [p["ParameterName"] for p in defaults.get("Parameters", [])]
        if pages == 1:
            first_page = names
            assert defaults.get("CacheParameterGroupFamily") == family, (
                f"EngineDefaults echoed family {defaults.get('CacheParameterGroupFamily')!r}, "
                f"requested {family!r}"
            )
        for p in defaults.get("Parameters", []):
            by_name[p["ParameterName"]] = p
        marker = defaults.get("Marker")
        if not marker or pages > 40:
            return by_name, pages, first_page


def _node_type_specific(ec, family):
    """The CacheNodeTypeSpecificParameters block for `family` (first page is enough)."""
    return ec.describe_engine_default_parameters(
        CacheParameterGroupFamily=family,
    )["EngineDefaults"].get("CacheNodeTypeSpecificParameters", [])


def _families(ec, engine):
    """The set of CacheParameterGroupFamily values DescribeCacheEngineVersions reports."""
    out = {}
    marker = None
    while True:
        kwargs = {"Engine": engine}
        if marker:
            kwargs["Marker"] = marker
        resp = ec.describe_cache_engine_versions(**kwargs)
        for v in resp.get("CacheEngineVersions", []):
            fam = v.get("CacheParameterGroupFamily")
            if fam:
                out.setdefault(fam, v)
        marker = resp.get("Marker")
        if not marker:
            return out


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Engine defaults carry in-enum ChangeType values, enumerated and ranged parameters, paginate,
    vary by node type, and differ between redis and memcached families; unknown family is refused.
    """
    ec = ctx.client("elasticache")

    # Families come from the version catalog rather than being hardcoded, so the check tracks new
    # engine versions.
    redis_families = _families(ec, "redis")
    memcached_families = _families(ec, "memcached")
    assert redis_families, "DescribeCacheEngineVersions(Engine='redis') reported no families"
    assert memcached_families, (
        "DescribeCacheEngineVersions(Engine='memcached') reported no families"
    )
    # Families sort lexically close enough to version order for 'pick the newest' here.
    redis_family = sorted(redis_families)[-1]
    memcached_family = sorted(memcached_families)[-1]
    assert redis_family != memcached_family, (
        f"redis and memcached must not share a parameter-group family: both are "
        f"{redis_family!r}"
    )

    # ---- ChangeType is populated, in-enum, and not uniformly 'immediate' ------------
    params, pages, first_page = _engine_defaults(ec, redis_family)
    assert len(params) >= 20, (
        f"{redis_family} published only {len(params)} default parameters; a real Redis "
        f"engine family has dozens (a stub catalog is the likely cause)"
    )

    missing_ct = sorted(n for n, p in params.items() if not p.get("ChangeType"))
    assert not missing_ct, (
        f"{len(missing_ct)} parameters in {redis_family} have no ChangeType, e.g. "
        f"{missing_ct[:5]}; ChangeType is a modeled enum member of the Parameter shape and "
        f"is how a client learns whether a reboot is required"
    )
    bad_ct = sorted(
        {p["ChangeType"] for p in params.values() if p["ChangeType"] not in _CHANGE_TYPES}
    )
    assert not bad_ct, (
        f"{redis_family} reported ChangeType values outside the modeled enum "
        f"{sorted(_CHANGE_TYPES)}: {bad_ct}"
    )
    reboot_required = sorted(
        n for n, p in params.items() if p["ChangeType"] == "requires-reboot"
    )
    assert reboot_required, (
        f"no parameter in {redis_family} is ChangeType='requires-reboot'; the "
        f"pending-reboot apply machine cannot exist if every parameter is immediate"
    )

    # ---- enumerated vs range-typed parameters are distinguishable -------------------
    policy = params.get("maxmemory-policy")
    assert policy is not None, (
        f"{redis_family} does not publish 'maxmemory-policy'; sample of what it does "
        f"publish: {sorted(params)[:15]}"
    )
    allowed = policy.get("AllowedValues") or ""
    assert "," in allowed, (
        f"maxmemory-policy AllowedValues must be a comma-separated enumeration, got "
        f"{allowed!r}"
    )
    members = {v.strip() for v in allowed.split(",")}
    for expected in ("allkeys-lru", "volatile-lru", "noeviction"):
        assert expected in members, (
            f"maxmemory-policy AllowedValues is missing the documented eviction policy "
            f"{expected!r}: {sorted(members)}"
        )
    assert policy.get("DataType") == "string", (
        f"maxmemory-policy DataType must be 'string', got {policy.get('DataType')!r}"
    )
    assert policy.get("IsModifiable") is True, (
        f"maxmemory-policy must be modifiable, got IsModifiable="
        f"{policy.get('IsModifiable')!r}"
    )

    ranged = {
        n: p for n, p in params.items()
        if p.get("DataType") == "integer" and _RANGE_RE.match(p.get("AllowedValues") or "")
    }
    assert ranged, (
        f"{redis_family} publishes no integer parameter with a range-shaped AllowedValues "
        f"(e.g. '0-'); DataType/AllowedValues are how value legality is expressed"
    )

    # ---- the catalog paginates -----------------------------------------------------
    assert pages >= 2, (
        f"DescribeEngineDefaultParameters(MaxRecords=20) returned {len(params)} parameters "
        f"in {pages} page(s); with MaxRecords=20 and {len(params)} parameters the catalog "
        f"must paginate via Marker"
    )
    assert len(first_page) <= 20, (
        f"MaxRecords=20 was ignored: the first page carried {len(first_page)} parameters"
    )
    assert set(first_page) != set(params), (
        "the Marker pagination returned the same page twice: the first page equals the "
        "full parameter set"
    )

    # ---- node-type-specific parameters actually vary by node type -------------------
    node_specific = _node_type_specific(ec, redis_family)
    assert node_specific, (
        f"{redis_family} published no CacheNodeTypeSpecificParameters; maxmemory and "
        f"friends are node-type dependent and this block is where that is expressed"
    )
    multi = [
        p for p in node_specific
        if len({v.get("CacheNodeType") for v in p.get("CacheNodeTypeSpecificValues", [])}) > 1
    ]
    assert multi, (
        f"no CacheNodeTypeSpecificParameter in {redis_family} lists values for more than "
        f"one CacheNodeType, so the block carries no node-type information"
    )
    sample = multi[0]
    values = {
        v["CacheNodeType"]: v.get("Value")
        for v in sample["CacheNodeTypeSpecificValues"]
    }
    assert len(set(values.values())) > 1, (
        f"CacheNodeTypeSpecificParameter {sample.get('ParameterName')!r} reports the same "
        f"value for every node type ({values}); a node-type-specific parameter that does "
        f"not vary is a stub"
    )

    # ---- two families return genuinely different catalogs --------------------------
    mem_params, _, _ = _engine_defaults(ec, memcached_family)
    assert mem_params, f"{memcached_family} published no default parameters"
    assert set(mem_params) != set(params), (
        f"{redis_family} and {memcached_family} returned the SAME parameter name set "
        f"({len(params)} names); the engine-default catalog must diverge by family"
    )
    assert "maxmemory-policy" not in mem_params, (
        f"'maxmemory-policy' is a Redis eviction parameter and must not appear in the "
        f"{memcached_family} defaults; the emulator is likely serving one catalog for all "
        f"families"
    )
    assert any(n.startswith("max_item_size") or n == "chunk_size" for n in mem_params), (
        f"{memcached_family} defaults contain no recognisable memcached parameter "
        f"(max_item_size / chunk_size); sample: {sorted(mem_params)[:15]}"
    )

    # ---- an unknown family is refused, not answered with a default catalog ----------
    bogus = "sim2real-not-a-family"
    code = _error_code(
        lambda: ec.describe_engine_default_parameters(CacheParameterGroupFamily=bogus)
    )
    assert code.startswith("InvalidParameterValue"), (
        f"DescribeEngineDefaultParameters({bogus!r}) returned {code}, expected "
        f"InvalidParameterValue"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

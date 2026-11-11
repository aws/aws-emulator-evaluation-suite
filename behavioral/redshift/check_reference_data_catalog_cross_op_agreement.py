"""reference-data-catalog-cross-op-agreement."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reference-data-catalog-cross-op-agreement"
GROUP = 'reference-data'
SERVICES = ['redshift']


# ===== helpers =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

_NOT_FOUND_PARAM_GROUP = (
    "ClusterParameterGroupNotFound",
    "ClusterParameterGroupNotFoundFault",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _delete_parameter_group(rs, name):
    try:
        rs.delete_cluster_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_PARAM_GROUP:
            return
        raise


def _paginate(fn, key, **kwargs):
    """Drain a Marker-paginated redshift describe into one list."""
    out = []
    marker = None
    while True:
        call = dict(kwargs)
        call["MaxRecords"] = 100
        if marker:
            call["Marker"] = marker
        resp = _retrying(lambda: fn(**call))
        out.extend(resp.get(key, []))
        marker = resp.get("Marker")
        if not marker:
            break
    return out


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Redshift reference-data describes agree with each other (versions, families, tracks), their
    NodeType/ClusterVersion filters narrow results, and a fresh parameter group reports the
    family defaults. Callers choose node types from these ops, so ignored filters break them.
    """
    rs = ctx.client("redshift")

    versions = _paginate(rs.describe_cluster_versions, "ClusterVersions")
    assert versions, "DescribeClusterVersions must not be empty"
    version_ids = {v["ClusterVersion"] for v in versions}
    families = {v["ClusterParameterGroupFamily"] for v in versions}
    assert families, f"every cluster version must name a parameter group family, got {versions[:3]!r}"

    options = _paginate(rs.describe_orderable_cluster_options, "OrderableClusterOptions")
    assert options, "DescribeOrderableClusterOptions must not be empty"
    for opt in options:
        assert opt["ClusterType"] in ("single-node", "multi-node"), (
            f"unexpected ClusterType in orderable options: {opt.get('ClusterType')!r}"
        )
        assert opt.get("NodeType"), f"an orderable option must name a NodeType: {opt!r}"
        assert opt.get("AvailabilityZones"), (
            f"an orderable option must list AvailabilityZones: {opt!r}"
        )

    # Cross-op agreement: no orderable option may advertise a version the version catalog
    # does not know about.
    orphan_versions = sorted({opt["ClusterVersion"] for opt in options} - version_ids)
    assert not orphan_versions, (
        "every orderable option's ClusterVersion must appear in DescribeClusterVersions; "
        f"{orphan_versions} do not"
    )

    # Filters must narrow. Pick a NodeType/ClusterVersion pair that demonstrably exists.
    node_types = sorted({opt["NodeType"] for opt in options})
    assert len(node_types) >= 2, (
        f"need at least two distinct orderable node types to prove filtering, got {node_types}"
    )
    target_node = node_types[0]
    expected_for_node = [opt for opt in options if opt["NodeType"] == target_node]
    filtered = _paginate(
        rs.describe_orderable_cluster_options, "OrderableClusterOptions", NodeType=target_node
    )
    assert filtered, f"filtering by the existing NodeType {target_node!r} returned nothing"
    stray = sorted({opt["NodeType"] for opt in filtered} - {target_node})
    assert not stray, (
        f"DescribeOrderableClusterOptions(NodeType={target_node!r}) must return only that node "
        f"type; the NodeType filter is being ignored (also returned {stray})"
    )
    assert len(filtered) == len(expected_for_node), (
        f"the NodeType filter must return exactly the {len(expected_for_node)} matching options, "
        f"got {len(filtered)}"
    )

    target_version = sorted({opt["ClusterVersion"] for opt in options})[0]
    by_version = _paginate(
        rs.describe_orderable_cluster_options,
        "OrderableClusterOptions",
        ClusterVersion=target_version,
    )
    assert by_version, f"filtering by the existing ClusterVersion {target_version!r} returned nothing"
    stray_versions = sorted({opt["ClusterVersion"] for opt in by_version} - {target_version})
    assert not stray_versions, (
        f"DescribeOrderableClusterOptions(ClusterVersion={target_version!r}) must return only "
        f"that version; the filter is being ignored (also returned {stray_versions})"
    )

    # Maintenance tracks are their own catalog and must reference real database versions.
    tracks = _paginate(rs.describe_cluster_tracks, "MaintenanceTracks")
    assert tracks, "DescribeClusterTracks must not be empty"
    track_names = {t["MaintenanceTrackName"] for t in tracks}
    assert "current" in track_names, (
        f"the 'current' maintenance track must exist, got {sorted(track_names)}"
    )
    for track in tracks:
        assert track.get("DatabaseVersion"), (
            f"a maintenance track must report its DatabaseVersion: {track!r}"
        )

    # Every family the version catalog advertises must be resolvable by the defaults op.
    family = sorted(families)[0]
    defaults = _retrying(
        lambda: rs.describe_default_cluster_parameters(ParameterGroupFamily=family)
    )["DefaultClusterParameters"]
    assert defaults["ParameterGroupFamily"] == family, (
        f"the response must echo the requested family {family!r}, got "
        f"{defaults.get('ParameterGroupFamily')!r}"
    )
    default_params = {p["ParameterName"]: p for p in defaults["Parameters"]}
    if not default_params:
        raise AssertionError(f"family {family} reported no default parameters on the first page")
    for name in ("require_ssl", "wlm_json_configuration"):
        assert name in default_params, (
            f"family {family} must expose the {name!r} default, got {sorted(default_params)!r}"
        )
    not_engine = sorted(
        n for n, p in default_params.items() if p.get("Source") != "engine-default"
    )
    assert not not_engine, (
        "every parameter from DescribeDefaultClusterParameters must have Source "
        f"'engine-default'; {not_engine} do not"
    )

    # Cross-op agreement against live state: a fresh group's values ARE the catalog defaults.
    group = ctx.unique_name("sim2real-behav-rs-catalog-")
    ctx.on_cleanup(lambda: _delete_parameter_group(rs, group))
    _retrying(
        lambda: rs.create_cluster_parameter_group(
            ParameterGroupName=group,
            ParameterGroupFamily=family,
            Description="sim2real catalog agreement probe",
            Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        )
    )
    fresh = {
        p["ParameterName"]: p
        for p in _paginate(rs.describe_cluster_parameters, "Parameters", ParameterGroupName=group)
    }
    shared = sorted(set(fresh) & set(default_params))
    assert shared, (
        f"a fresh {family} group shares no parameter names with the family defaults: "
        f"{sorted(fresh)[:5]!r} vs {sorted(default_params)[:5]!r}"
    )
    mismatched = {
        name: (default_params[name].get("ParameterValue"), fresh[name].get("ParameterValue"))
        for name in shared
        if default_params[name].get("ParameterValue") != fresh[name].get("ParameterValue")
    }
    assert not mismatched, (
        "an unmodified parameter group must report exactly the family's engine defaults; "
        f"catalog vs group disagreement: {mismatched}"
    )
    type_mismatch = {
        name: (default_params[name].get("DataType"), fresh[name].get("DataType"))
        for name in shared
        if default_params[name].get("DataType") != fresh[name].get("DataType")
    }
    assert not type_mismatch, (
        f"parameter DataType must agree between the catalog and the group: {type_mismatch}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

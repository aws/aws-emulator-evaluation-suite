"""describe-cluster-parameters."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-cluster-parameters"
GROUP = 'cluster_parameter_groups'
SERVICES = ['rds']


def _client_error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _default_param_family(rds, engine):
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["DBParameterGroupFamily"]


def _engine_default_names(rds, family):
    names = set()
    paginator = rds.get_paginator("describe_engine_default_cluster_parameters")
    for page in paginator.paginate(DBParameterGroupFamily=family):
        for p in page["EngineDefaults"]["Parameters"]:
            names.add(p["ParameterName"])
    return names


def _group_param_names(rds, name):
    names = set()
    paginator = rds.get_paginator("describe_db_cluster_parameters")
    for page in paginator.paginate(DBClusterParameterGroupName=name):
        for p in page.get("Parameters", []):
            names.add(p["ParameterName"])
    return names


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBClusterParameters: a freshly created cluster parameter group is pre-populated with
    the engine's full default parameter set, visible immediately with no cluster attachment
    required. Error boundary: an unknown group name rejects with DBParameterGroupNotFound.
    """
    rds = ctx.client("rds")
    family = _default_param_family(rds, "aurora-mysql")
    name = ctx.unique_name("sim2real-behav-cpg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=name,
        DBParameterGroupFamily=family,
        Description="behavioral check",
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=name))

    group_names = _poll_until(
        lambda: _group_param_names(rds, name),
        lambda p: len(p) > 0,
        timeout_s=60,
        interval_s=3,
        description=f"parameters populated for {name}",
    )

    default_names = _engine_default_names(rds, family)
    assert default_names, f"no engine-default cluster parameters reported for family {family!r}"
    missing = default_names - group_names
    assert not missing, (
        f"freshly created cluster parameter group {name!r} is missing "
        f"{len(missing)} of the {len(default_names)} parameter(s) in family {family!r}'s engine "
        f"defaults -- not pre-populated with the full default set: {sorted(missing)[:5]}"
    )

    bogus_name = ctx.unique_name("sim2real-behav-cpg-missing-")
    code, message = _client_error(
        lambda: rds.describe_db_cluster_parameters(DBClusterParameterGroupName=bogus_name)
    )
    assert code == "DBParameterGroupNotFound", f"unexpected error code: {code}"
    assert message == f"DBClusterParameterGroup not found: {bogus_name}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

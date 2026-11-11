"""parameter-group-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "parameter-group-numeric-precision-preserved"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A numeric cluster parameter value set through ModifyClusterParameterGroup is
    returned unchanged -- as the exact same digit string, with no rounding,
    truncation, or reformatting -- by a subsequent DescribeClusterParameters."""
    redshift = ctx.client("redshift")

    group_name = ctx.unique_name("sim2real-numprec-pg-").lower()
    redshift.create_cluster_parameter_group(
        ParameterGroupName=group_name,
        ParameterGroupFamily="redshift-1.0",
        Description="sim2real numeric precision round trip",
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: redshift.delete_cluster_parameter_group(ParameterGroupName=group_name))

    def _find(name):
        """All parameters of *group_name*, keyed by ParameterName (paginated -- a fresh
        redshift-1.0 group exposes far more than the 100-record default page)."""
        out = {}
        marker = None
        while True:
            kwargs = {"ParameterGroupName": group_name, "MaxRecords": 100}
            if marker:
                kwargs["Marker"] = marker
            resp = redshift.describe_cluster_parameters(**kwargs)
            for param in resp["Parameters"]:
                out[param["ParameterName"]] = param
            marker = resp.get("Marker")
            if not marker:
                break
        assert name in out, f"{name!r} parameter missing from parameter group, got {sorted(out)!r}"
        return out[name]

    # statement_timeout is documented as an integer number of milliseconds; use a
    # deliberately non-round value to detect any server-side rounding/truncation, and a
    # second value with leading zeros to detect canonicalization/reformatting -- a value
    # that already looks canonical (like 123456789) would pass a reformatting bug silently.
    precise_value = "123456789"
    redshift.modify_cluster_parameter_group(
        ParameterGroupName=group_name,
        Parameters=[{"ParameterName": "statement_timeout", "ParameterValue": precise_value}],
    )

    match = _find("statement_timeout")
    assert match["ParameterValue"] == precise_value, (
        "numeric parameter value was altered: "
        f"expected {precise_value!r}, got {match['ParameterValue']!r}"
    )
    assert match["Source"] == "user", (
        f"an explicitly set parameter must report Source 'user', got {match.get('Source')!r}"
    )

    padded_value = "0000123456789"
    redshift.modify_cluster_parameter_group(
        ParameterGroupName=group_name,
        Parameters=[{"ParameterName": "statement_timeout", "ParameterValue": padded_value}],
    )
    padded_match = _find("statement_timeout")
    assert padded_match["ParameterValue"] == padded_value, (
        "a leading-zero-padded numeric parameter value was reformatted: "
        f"expected {padded_value!r}, got {padded_match['ParameterValue']!r}"
    )
    assert padded_match["Source"] == "user", (
        f"an explicitly set parameter must report Source 'user', got {padded_match.get('Source')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

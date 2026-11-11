"""parameter-group-known-parameter-value-validation."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-group-known-parameter-value-validation"
GROUP = 'overly-permissive'
SERVICES = ['redshift']


# ===== helpers =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

# Provisioned Redshift has exactly one parameter group family.
PARAMETER_GROUP_FAMILY = "redshift-1.0"
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


def _err(fn):
    """Call *fn*; return the (code, message) of the AWS error it raises, or ("OK", None)."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    return "OK", None


def _delete_parameter_group(rs, name):
    """Parameter groups are free but they consume a per-account quota, so they still need
    their own cleanup; a group attached to no cluster deletes immediately."""
    try:
        rs.delete_cluster_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if _code_of(exc) not in _NOT_FOUND_PARAM_GROUP:
            raise


def _parameters(rs, name):
    """All parameters of *name*, keyed by ParameterName (paginated)."""
    out = {}
    marker = None
    while True:
        kwargs = {"ParameterGroupName": name, "MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_cluster_parameters(**kwargs))
        for param in resp.get("Parameters", []):
            out[param["ParameterName"]] = param
        marker = resp.get("Marker")
        if not marker:
            break
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A known parameter given an invalid value is rejected with the stored value untouched, and a
    partially-invalid ModifyClusterParameterGroup is rejected in its entirety; a legal value and
    ResetClusterParameterGroup succeed as the control."""
    rs = ctx.client("redshift")

    group = ctx.unique_name("sim2real-behav-rs-pg-")
    ctx.on_cleanup(lambda: _delete_parameter_group(rs, group))
    created = _retrying(
        lambda: rs.create_cluster_parameter_group(
            ParameterGroupName=group,
            ParameterGroupFamily=PARAMETER_GROUP_FAMILY,
            Description="sim2real value-validation probe",
            Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        )
    )["ClusterParameterGroup"]
    assert created["ParameterGroupName"] == group, created
    assert created["ParameterGroupFamily"] == PARAMETER_GROUP_FAMILY, created

    baseline = _parameters(rs, group)
    for name in ("require_ssl", "wlm_json_configuration", "statement_timeout"):
        assert name in baseline, (
            f"a fresh {PARAMETER_GROUP_FAMILY} group must expose the {name!r} parameter, got "
            f"{sorted(baseline)!r}"
        )
    assert baseline["require_ssl"]["Source"] == "engine-default", (
        f"an unmodified parameter must report Source 'engine-default', got "
        f"{baseline['require_ssl'].get('Source')!r}"
    )
    assert baseline["require_ssl"]["DataType"] == "boolean", (
        f"require_ssl must be typed boolean, got {baseline['require_ssl'].get('DataType')!r}"
    )
    assert baseline["statement_timeout"]["DataType"] == "integer", (
        f"statement_timeout must be typed integer, got "
        f"{baseline['statement_timeout'].get('DataType')!r}"
    )

    def _modify(*params):
        return lambda: rs.modify_cluster_parameter_group(
            ParameterGroupName=group, Parameters=list(params)
        )

    # Break exactly one thing per leg: the parameter NAME is valid every time, only the
    # VALUE violates the parameter's declared domain.
    bad_boolean, message = _err(_modify({"ParameterName": "require_ssl", "ParameterValue": "maybe"}))
    assert bad_boolean == "InvalidParameterValue", (
        f"a boolean parameter given 'maybe' must be rejected, got {bad_boolean}"
    )
    assert message == "parameter value is not a valid boolean:maybe", message

    bad_json, message = _err(
        _modify({"ParameterName": "wlm_json_configuration", "ParameterValue": "{not-valid-json"})
    )
    assert bad_json == "InvalidParameterValue", (
        f"wlm_json_configuration given malformed JSON must be rejected, got {bad_json}"
    )
    assert message == "Invalid JSON for wlm_json_configuration", message

    bad_integer, message = _err(
        _modify({"ParameterName": "statement_timeout", "ParameterValue": "soon"})
    )
    assert bad_integer == "InvalidParameterValue", (
        f"an integer parameter given 'soon' must be rejected, got {bad_integer}"
    )
    assert message == "invalid integer value:soon", message

    # Effect absent after all three rejections: every stored value is byte-for-byte the default.
    after_rejections = _parameters(rs, group)
    for name in ("require_ssl", "wlm_json_configuration", "statement_timeout"):
        assert after_rejections[name].get("ParameterValue") == baseline[name].get("ParameterValue"), (
            f"a rejected modify must leave {name} unchanged; was "
            f"{baseline[name].get('ParameterValue')!r}, now "
            f"{after_rejections[name].get('ParameterValue')!r}"
        )
        assert after_rejections[name]["Source"] == "engine-default", (
            f"a rejected modify must not flip {name} to Source 'user', got "
            f"{after_rejections[name].get('Source')!r}"
        )

    # Atomicity: one valid + one invalid parameter in the same call. The whole call must fail
    # and the valid half must NOT be applied.
    mixed, message = _err(
        _modify(
            {"ParameterName": "require_ssl", "ParameterValue": "true"},
            {"ParameterName": "statement_timeout", "ParameterValue": "-5"},
        )
    )
    assert mixed == "InvalidParameterValue", (
        f"a modify containing an out-of-range value must be rejected wholesale, got {mixed}"
    )
    assert message == "The statement_timeout of -5 is outside of the acceptable range of 0,100-2147483647", message
    after_mixed = _parameters(rs, group)
    assert after_mixed["require_ssl"].get("ParameterValue") == baseline["require_ssl"].get(
        "ParameterValue"
    ), (
        "ModifyClusterParameterGroup must be atomic: the valid parameter in a rejected call "
        f"must not be applied, but require_ssl is now "
        f"{after_mixed['require_ssl'].get('ParameterValue')!r}"
    )

    # Control: the identical call shape with legal values succeeds and is visibly applied.
    wlm = json.dumps(
        [
            {"query_group": [], "query_group_wild_card": 0, "user_group": [],
             "user_group_wild_card": 0, "query_concurrency": 5},
            {"short_query_queue": False},
        ]
    )
    applied = _retrying(
        _modify(
            {"ParameterName": "require_ssl", "ParameterValue": "true"},
            {"ParameterName": "statement_timeout", "ParameterValue": "60000"},
            {"ParameterName": "wlm_json_configuration", "ParameterValue": wlm},
        )
    )
    assert applied["ParameterGroupName"] == group, applied
    assert applied.get("ParameterGroupStatus"), (
        f"ModifyClusterParameterGroup must report a ParameterGroupStatus, got {applied!r}"
    )

    modified = _parameters(rs, group)
    assert modified["require_ssl"]["ParameterValue"] == "true", modified["require_ssl"]
    assert modified["require_ssl"]["Source"] == "user", (
        f"an explicitly set parameter must report Source 'user', got "
        f"{modified['require_ssl'].get('Source')!r}"
    )
    assert modified["statement_timeout"]["ParameterValue"] == "60000", modified["statement_timeout"]
    assert json.loads(modified["wlm_json_configuration"]["ParameterValue"]) == json.loads(wlm), (
        "the stored WLM configuration must round-trip as the same JSON document, got "
        f"{modified['wlm_json_configuration'].get('ParameterValue')!r}"
    )
    assert modified["require_ssl"]["ApplyType"] in ("static", "dynamic"), (
        f"every parameter must declare an ApplyType, got {modified['require_ssl'].get('ApplyType')!r}"
    )

    # Reset returns the group to engine defaults, undoing the Source flip.
    reset = _retrying(
        lambda: rs.reset_cluster_parameter_group(
            ParameterGroupName=group, ResetAllParameters=True
        )
    )
    assert reset["ParameterGroupName"] == group, reset
    final = _parameters(rs, group)
    assert final["require_ssl"].get("ParameterValue") == baseline["require_ssl"].get(
        "ParameterValue"
    ), (
        "ResetClusterParameterGroup(ResetAllParameters=True) must restore the default value, "
        f"got {final['require_ssl'].get('ParameterValue')!r}"
    )
    assert final["require_ssl"]["Source"] == "engine-default", (
        f"a reset parameter must report Source 'engine-default' again, got "
        f"{final['require_ssl'].get('Source')!r}"
    )
    assert final["statement_timeout"].get("ParameterValue") == baseline["statement_timeout"].get(
        "ParameterValue"
    ), final["statement_timeout"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""batch-get-security-controls-parameter-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-get-security-controls-parameter-round-trip"
GROUP = "data-plane"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """UpdateSecurityControl sets a custom boolean parameter, and BatchGetSecurityControls reflects the new value."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    control_id, param_name, default_value = _find_boolean_param_control(sh)
    if control_id is None:
        raise AssertionError(
            "no security control definition in this account/region exposes a customizable "
            "boolean parameter, so UpdateSecurityControl's parameter round trip cannot be exercised"
        )

    custom_value = not default_value
    sh.update_security_control(
        SecurityControlId=control_id,
        Parameters={param_name: {"ValueType": "CUSTOM", "Value": {"Boolean": custom_value}}},
        LastUpdateReason="sim2real behavioral test parameter round trip",
    )

    def _cleanup():
        sh.update_security_control(SecurityControlId=control_id, Parameters={param_name: {"ValueType": "DEFAULT"}})

    ctx.on_cleanup(_cleanup)

    updated = _poll_until(
        lambda: sh.batch_get_security_controls(SecurityControlIds=[control_id])["SecurityControls"][0],
        lambda c: c["Parameters"][param_name]["Value"]["Boolean"] == custom_value,
        timeout_s=60,
        interval_s=3,
    )
    got_value_type = updated["Parameters"][param_name]["ValueType"]
    assert got_value_type == "CUSTOM", f"expected ValueType CUSTOM after the update, got {got_value_type!r}"
    got_bool = updated["Parameters"][param_name]["Value"]["Boolean"]
    assert got_bool == custom_value, f"expected {param_name}={custom_value!r} via BatchGetSecurityControls, got {got_bool!r}"


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


def _find_boolean_param_control(sh):
    """ListSecurityControlDefinitions never populates ParameterDefinitions; only
    GetSecurityControlDefinition does, so candidates are found by listing and confirmed one by one."""
    next_token = None
    candidate_ids = []
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = sh.list_security_control_definitions(**kwargs)
        for definition in resp.get("SecurityControlDefinitions", []):
            if "Parameters" in (definition.get("CustomizableProperties") or []):
                candidate_ids.append(definition["SecurityControlId"])
        next_token = resp.get("NextToken")
        if not next_token:
            break

    for control_id in candidate_ids:
        defn = sh.get_security_control_definition(SecurityControlId=control_id)["SecurityControlDefinition"]
        for name, pdef in (defn.get("ParameterDefinitions") or {}).items():
            opts = pdef.get("ConfigurationOptions", {})
            if "Boolean" in opts:
                return control_id, name, opts["Boolean"].get("DefaultValue", False)
    return None, None, None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

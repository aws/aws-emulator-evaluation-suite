"""batch-update-action-unknown-service-update."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")

def _refusal(fn):
    """(code without its modeled Fault/Exception suffix, message) of the error fn() raises."""
    code, message = _error(fn)
    return _fault_base(code), message

CHECK = "batch-update-action-unknown-service-update"
GROUP = 'service-update'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Batch{Apply,Stop}UpdateAction with a service update name that does not exist raises
    ServiceUpdateNotFoundFault, while the identical call with a real, catalogued service update
    name does not, so the fault keys on the unknown name."""
    ec = ctx.client("elasticache")
    bogus_update = ctx.unique_name("sim2real-behav-esu-")
    bogus_rg = ctx.unique_name("sim2real-behav-erg-upd-")

    catalog = ec.describe_service_updates().get("ServiceUpdates", [])
    assert catalog, "account/region has no catalogued service updates at all; cannot form a positive control"
    real_update = catalog[0]["ServiceUpdateName"]

    for op in (ec.batch_apply_update_action, ec.batch_stop_update_action):
        try:
            op(ServiceUpdateName=real_update, ReplicationGroupIds=[bogus_rg])
            code = None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
        assert code is None or _fault_base(code) != _fault_base("ServiceUpdateNotFoundFault"), (
            f"a real, catalogued service update name ({real_update}) still raised "
            f"ServiceUpdateNotFoundFault via {op.__name__}; the check cannot distinguish "
            "an unknown-name rejection from a blanket rejection"
        )

    refused = _refusal(
        lambda: ec.batch_apply_update_action(
            ServiceUpdateName=bogus_update, ReplicationGroupIds=[bogus_rg],
        ),
    )
    assert refused == (
        "ServiceUpdateNotFound",
        f"ServiceUpdate {bogus_update} not found.",
    ), f"expected ServiceUpdateNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.batch_stop_update_action(
            ServiceUpdateName=bogus_update, ReplicationGroupIds=[bogus_rg],
        ),
    )
    assert refused == (
        "ServiceUpdateNotFound",
        f"ServiceUpdate {bogus_update} not found.",
    ), f"expected ServiceUpdateNotFound with its exact message, got {refused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

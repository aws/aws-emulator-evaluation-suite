"""insights-management."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "insights-management"
GROUP = 'domain'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _never_ready(msg: str) -> AssertionError:
    """The error for a resource that never converged; returned to keep ``from exc`` chaining."""
    return AssertionError(msg)


def _create_domain(ctx, osc, domain_name) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        # Tagged at creation so tag-based cleanup can find it if this check's cleanup never runs.
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    for _attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if _attempt == 0 else 6.0 * _attempt + random.uniform(0, 6.0))
        try:
            resp = osc.create_domain(**kwargs)
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    return resp["DomainStatus"]


def _wait_domain_active(ctx, osc, domain_name, timeout_s: float = 1450) -> dict:
    """Poll until Processing=False and Created=True; a domain needs 10-20 min to go Active."""
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2)
    raise _never_ready(
        f"domain {domain_name} never became Active within {budget}s",
    )


def _error(fn) -> "tuple[str, str]":
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInsights on a domain entity returns an Insights list, DescribeInsightDetails returns
    informational Fields for any valid insight id, and an Entity.Type outside
    [Account, DomainName] is rejected with ValidationException and the exact message."""
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain)
    _wait_domain_active(ctx, osc, domain)
    entity = {"Type": "DomainName", "Value": domain}

    listed = osc.list_insights(Entity=entity)
    assert isinstance(listed.get("Insights"), list), f"expected an Insights list, got {listed}"

    bogus_insight_id = "00000000-0000-0000-0000-000000000000"

    # DescribeInsightDetails answers any syntactically valid InsightId with a generic
    # informational Field (pointing to the console), so this is not a not-found boundary.
    details = osc.describe_insight_details(Entity=entity, InsightId=bogus_insight_id)
    fields = details.get("Fields", [])
    assert fields, f"expected at least one informational Field, got {details}"
    assert all("Name" in f and "Value" in f for f in fields), fields

    # ListInsights answers an unknown domain with an empty list, not a not-found, so the
    # negative case here is the Entity.Type enum.
    code2, message2 = _error(
        lambda: osc.list_insights(Entity={"Type": "DOMAIN", "Value": domain})
    )
    # The same call with Type="DomainName" succeeded above, so the rejection is keyed on the enum.
    assert code2 == "ValidationException", f"expected ValidationException, got {code2}"
    assert message2 == (
        "1 validation error detected: Value 'DOMAIN' at 'entity.type' failed to satisfy "
        "constraint: Member must satisfy enum value set: [Account, DomainName]"
    ), (
        f"unexpected ListInsights enum refusal message: {message2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

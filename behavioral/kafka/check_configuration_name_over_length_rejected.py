"""configuration-name-over-length-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-name-over-length-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

# CreateConfigurationRequest.Name is plain `__string` in the Smithy model -- no min, no max,
# no pattern -- so botocore performs NO client-side validation and the whole name-legality
# contract is enforced server-side only. That makes it a pure emulator-fidelity surface.
#
# MSK bounds configuration names to 1..128 characters, which the model and the docs do not
# state; the bound is not the 64 that CreateClusterV2 spells out for ClusterName
# (__stringMin1Max64). Lengths 64/65/100/128 are all ACCEPTED and round-trip byte-identical;
# 129/200/256/257/300/1024 and the empty string are all BadRequestException / HTTP 400 with
# Message exactly "The resource name contains too many or too few characters".
_MAX_NAME_LEN = 128
_LEN_ERROR_MESSAGE = "The resource name contains too many or too few characters"
_PROPS = b"auto.create.topics.enable=true\n"
_KAFKA_VERSION = "3.9.x"


def _poll(fn, pred, *, timeout_s, interval_s, description="condition"):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _fail(fn):
    """Invoke fn(); return (error_code, http_status, message). Raise if it unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


def _paginate(fn, list_key, **kwargs):
    items, token = [], None
    for _ in range(200):
        page_kwargs = dict(kwargs)
        if token:
            page_kwargs["NextToken"] = token
        resp = fn(**page_kwargs)
        items.extend(resp.get(list_key, []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A 128-character configuration name is created ACTIVE and read back intact; 129 characters and the
    empty name both fail with BadRequestException 400 and the same length message, and neither the long
    name nor a truncation is created."""
    msk = ctx.client("kafka")

    # --- full valid setup: a name at exactly the documented limit --------------------
    prefix = ctx.unique_name("sim2real-behav-cfgname-")
    assert len(prefix) <= _MAX_NAME_LEN, (
        f"ctx.unique_name produced a {len(prefix)}-char prefix, longer than the "
        f"{_MAX_NAME_LEN}-char name limit this check needs to pad up to: {prefix!r}"
    )
    at_limit = prefix + ("a" * (_MAX_NAME_LEN - len(prefix)))
    assert len(at_limit) == _MAX_NAME_LEN, at_limit

    control = msk.create_configuration(
        Name=at_limit, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_PROPS
    )
    control_arn = control["Arn"]
    ctx.on_cleanup(lambda _a=control_arn: msk.delete_configuration(Arn=_a))
    described = _poll(
        lambda: msk.describe_configuration(Arn=control_arn),
        lambda d: d.get("State") in ("ACTIVE", "DELETE_FAILED"),
        timeout_s=120,
        interval_s=3,
        description="at-limit configuration to reach ACTIVE",
    )
    assert described["State"] == "ACTIVE", described
    assert described["Name"] == at_limit, (
        f"a name at the {_MAX_NAME_LEN}-char limit must round-trip byte-identical: "
        f"sent {at_limit!r}, got {described['Name']!r}"
    )

    # --- break exactly one thing: one character past the limit -----------------------
    over_limit = at_limit[:-1] + "bc"
    assert len(over_limit) == _MAX_NAME_LEN + 1, over_limit
    code, status, msg = _fail(
        lambda: msk.create_configuration(
            Name=over_limit, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_PROPS
        )
    )
    assert code == "BadRequestException", (
        f"a {_MAX_NAME_LEN + 1}-character configuration name must be BadRequestException, "
        f"got {code} (HTTP {status})"
    )
    assert status == 400, f"expected HTTP 400, got {status}"
    assert msg == _LEN_ERROR_MESSAGE, (
        f"the rejection must name the length constraint ({_LEN_ERROR_MESSAGE!r}), not some "
        f"unrelated failure that happens to be a 400: {msg!r}"
    )

    # --- the other end of the SAME bound: the empty name, same code and message -------
    empty_code, empty_status, empty_msg = _fail(
        lambda: msk.create_configuration(
            Name="", KafkaVersions=[_KAFKA_VERSION], ServerProperties=_PROPS
        )
    )
    assert (empty_code, empty_status) == ("BadRequestException", 400), (
        f"an empty configuration name must be BadRequestException/400, got {empty_code} "
        f"(HTTP {empty_status})"
    )
    assert empty_msg == _LEN_ERROR_MESSAGE, (
        f"the empty name must be refused by the same length constraint as the over-long one "
        f"({_LEN_ERROR_MESSAGE!r}): {empty_msg!r}"
    )

    # --- the effect must be absent, and must not be a truncation ---------------------
    names = {c["Name"] for c in _paginate(msk.list_configurations, "Configurations")}
    assert over_limit not in names, f"the over-long name {over_limit!r} was stored anyway"
    truncated = over_limit[:_MAX_NAME_LEN]
    assert truncated not in names or truncated == at_limit, (
        f"the over-long name was silently truncated to {truncated!r} and created"
    )

    # --- the control case must still work -------------------------------------------
    still = msk.describe_configuration(Arn=control_arn)
    assert still["Name"] == at_limit, still["Name"]
    assert still["LatestRevision"]["Revision"] == 1, still["LatestRevision"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""configuration-arn-region-scope-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-arn-region-scope-enforced"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_PROPS = b"auto.create.topics.enable=true\n"
_KAFKA_VERSION = "3.9.x"
# Two real, standard partitions-of-one regions used only as ARN text. Nothing is called in
# them: the request always goes to ctx.region's endpoint; only the ARN's region segment moves.
_FOREIGN_REGIONS = ("us-east-2", "eu-west-1", "us-west-1", "ap-southeast-1")
# A region segment that is not any real region. Real MSK discriminates this from a real foreign
# region: see the run() docstring.
_BOGUS_REGION = "xx-fake-1"
_NOT_FOUND_MESSAGE = "The requested resource doesn\u2019t exist."
_INVALID_PARAMETERS_MESSAGE = "One or more of the parameters are not valid."


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
            exc.response.get("Error", {}).get("Message"),
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


def _reregion(arn: str, region: str) -> str:
    """Return arn with only its region segment replaced. Everything else is byte-identical."""
    parts = arn.split(":")
    assert len(parts) >= 6, f"unexpected ARN shape: {arn!r}"
    parts[3] = region
    return ":".join(parts)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A configuration ARN with only its region rewritten to another real region fails Describe,
    DescribeRevision and Update with NotFoundException 404, a non-region segment fails with
    BadRequestException 400, and the original ARN still resolves."""
    msk = ctx.client("kafka")

    # --- full valid setup: a real configuration, read through its own ARN ------------
    name = ctx.unique_name("sim2real-behav-config-arnscope-")
    created = msk.create_configuration(
        Name=name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_PROPS
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda _a=arn: msk.delete_configuration(Arn=_a))
    # CreateConfiguration has no Tags parameter, and MSK's TagResource rejects a
    # configuration ARN outright (BadRequestException "Invalid input resource
    # arn") -- configurations are not a taggable resource type, so this configuration is
    # not tagged.
    described = _poll(
        lambda: msk.describe_configuration(Arn=arn),
        lambda d: d.get("State") in ("ACTIVE", "DELETE_FAILED"),
        timeout_s=120,
        interval_s=3,
        description="configuration to reach ACTIVE",
    )
    assert described["State"] == "ACTIVE", described
    assert described["Arn"] == arn, f"DescribeConfiguration echoed a different ARN: {described['Arn']}"

    foreign = next((r for r in _FOREIGN_REGIONS if r != ctx.region), None)
    if foreign is None:
        raise AssertionError(f"no foreign region available to rewrite into for {ctx.region}")
    foreign_arn = _reregion(arn, foreign)
    assert foreign_arn != arn, foreign_arn
    # Exactly one segment differs.
    assert [a == b for a, b in zip(arn.split(":"), foreign_arn.split(":"))].count(False) == 1, (
        f"the rewrite changed more than the region segment: {arn} vs {foreign_arn}"
    )

    # --- the read must be refused ----------------------------------------------------
    read_code, read_status, read_msg = _fail(lambda: msk.describe_configuration(Arn=foreign_arn))
    assert read_code == "NotFoundException", (
        f"DescribeConfiguration with a {foreign} ARN against the {ctx.region} endpoint must be "
        f"NotFoundException, got {read_code} (HTTP {read_status}); resolving it to the local "
        f"configuration means the region segment is being ignored"
    )
    assert read_status == 404, f"expected HTTP 404, got {read_status}"
    assert read_msg == _NOT_FOUND_MESSAGE, read_msg

    # A revision read through the same rewritten ARN is scoped identically -- the region guard
    # is on the ARN, not on the one operation.
    rev_code, rev_status, rev_msg = _fail(
        lambda: msk.describe_configuration_revision(Arn=foreign_arn, Revision=1)
    )
    assert (rev_code, rev_status) == ("NotFoundException", 404), (
        f"DescribeConfigurationRevision with a {foreign} ARN must be NotFoundException/404, got "
        f"{rev_code} (HTTP {rev_status})"
    )
    assert rev_msg == _NOT_FOUND_MESSAGE, rev_msg

    # --- the write must be refused too (a read-only guard is not enough) -------------
    write_code, write_status, write_msg = _fail(
        lambda: msk.update_configuration(
            Arn=foreign_arn, ServerProperties=_PROPS + b"num.partitions=5\n"
        )
    )
    assert write_code == "NotFoundException", (
        f"UpdateConfiguration with a {foreign} ARN must be NotFoundException, got "
        f"{write_code} (HTTP {write_status})"
    )
    assert write_status == 404, f"expected HTTP 404, got {write_status}"
    assert write_msg == _NOT_FOUND_MESSAGE, write_msg

    # --- a region segment that is not a region at all is a different, earlier rejection ----
    bogus_arn = _reregion(arn, _BOGUS_REGION)
    bogus_code, bogus_status, bogus_msg = _fail(lambda: msk.describe_configuration(Arn=bogus_arn))
    assert bogus_code == "BadRequestException", (
        f"DescribeConfiguration with the non-region segment {_BOGUS_REGION!r} must be "
        f"BadRequestException (ARN validation, before any lookup), got {bogus_code} "
        f"(HTTP {bogus_status})"
    )
    assert bogus_status == 400, f"expected HTTP 400, got {bogus_status}"
    assert bogus_msg == _INVALID_PARAMETERS_MESSAGE, bogus_msg

    # --- the effect must be absent and the control case must still work --------------
    still = msk.describe_configuration(Arn=arn)
    assert still["State"] == "ACTIVE", still
    assert still["LatestRevision"]["Revision"] == 1, (
        f"the refused cross-region update landed on the local configuration anyway: "
        f"{still['LatestRevision']}"
    )
    props = msk.describe_configuration_revision(Arn=arn, Revision=1)["ServerProperties"]
    assert b"num.partitions" not in bytes(props), (
        f"the refused cross-region update's properties were written to revision 1: {props!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

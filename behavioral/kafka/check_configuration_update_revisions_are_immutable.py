"""configuration-update-revisions-are-immutable."""
from __future__ import annotations

import concurrent.futures
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-update-revisions-are-immutable"
GROUP = 'configuration'
SERVICES = ['kafka']

# Client-fault codes the MSK control plane is allowed to return for a rejected
# mutation. Used only where AWS's exact choice between NotFound/BadRequest is not
# contractually pinned; the determinism assertions below are the discriminators.
_CLIENT_FAULTS = {
    "NotFoundException",
    "BadRequestException",
    "ConflictException",
    "ForbiddenException",
    "UnauthorizedException",
    "TooManyRequestsException",
    "LimitExceededException",
}

# MSK's refusal for a configuration ARN or revision that does not exist.
_MISSING_ARN_MESSAGE = "Configuration ARN does not exist."


def _fail_info(fn):
    """Invoke fn(); return (error_code, http_status, message). Raise if it succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        meta = exc.response.get("ResponseMetadata", {})
        return err.get("Code"), meta.get("HTTPStatusCode"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


def _parse_props(blob) -> dict:
    if isinstance(blob, (bytes, bytearray)):
        text = bytes(blob).decode("utf-8")
    else:
        text = str(blob)
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    import time
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateConfiguration calls land on distinct revisions ending at the expected latest while
    revision 1 stays unchanged, and a stale or unknown revision or ARN fails with BadRequestException 400
    and its exact message."""
    msk = ctx.client("kafka")
    server_props = b"auto.create.topics.enable=true\n"
    config_name = ctx.unique_name("sim2real-behav-config-stalerev-")
    created = msk.create_configuration(
        Name=config_name, ServerProperties=server_props, KafkaVersions=["3.6.0"]
    )
    config_arn = created["Arn"]
    ctx.on_cleanup(lambda _a=config_arn: msk.delete_configuration(Arn=_a))

    described = _poll_until(
        lambda: msk.describe_configuration(Arn=config_arn),
        lambda d: d.get("State") in {"ACTIVE", "DELETE_FAILED"},
        description="configuration to reach ACTIVE",
    )
    assert described["State"] == "ACTIVE", f"configuration not ACTIVE: {described['State']}"
    assert described["Name"] == config_name
    base_rev = described["LatestRevision"]["Revision"]
    assert base_rev == 1, f"expected first revision to be 1, got {base_rev}"

    rev1 = msk.describe_configuration_revision(Arn=config_arn, Revision=1)
    rev1_props = _parse_props(rev1["ServerProperties"])
    assert rev1_props.get("auto.create.topics.enable") == "true", f"revision 1 props: {rev1_props}"
    assert "log.retention.hours" not in rev1_props, f"revision 1 unexpectedly has retention: {rev1_props}"

    # concurrent updates, all racing off the same stale revision 1
    n = 3

    def do_update(i):
        props = (
            b"auto.create.topics.enable=true\n"
            + f"log.retention.hours={168 + i}\n".encode("utf-8")
        )
        try:
            resp = msk.update_configuration(
                Arn=config_arn,
                ServerProperties=props,
                Description=f"concurrent-update-{i}",
            )
            return ("ok", resp["LatestRevision"]["Revision"])
        except ClientError as exc:
            return ("err", exc.response.get("Error", {}).get("Code"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(do_update, range(n)))

    ok_revs = [r for kind, r in results if kind == "ok"]
    err_codes = [r for kind, r in results if kind == "err"]

    assert ok_revs, f"expected at least one UpdateConfiguration to succeed, errors={err_codes}"
    for code in err_codes:
        assert code in _CLIENT_FAULTS, f"unexpected error code from UpdateConfiguration: {code}"

    # No two concurrent updates may report the same revision number.
    assert len(set(ok_revs)) == len(ok_revs), f"duplicate revision numbers handed out: {ok_revs}"
    assert all(r > base_rev for r in ok_revs), f"revisions must advance past {base_rev}: {ok_revs}"

    expected_latest = base_rev + len(ok_revs)
    assert max(ok_revs) == expected_latest, (
        f"revision numbering not contiguous: successes={ok_revs} expected latest={expected_latest}"
    )

    final = _poll_until(
        lambda: msk.describe_configuration(Arn=config_arn),
        lambda d: d["LatestRevision"]["Revision"] == expected_latest,
        description="DescribeConfiguration to converge on latest revision",
    )
    assert final["LatestRevision"]["Revision"] == expected_latest, final["LatestRevision"]
    assert final["State"] == "ACTIVE", f"configuration state after updates: {final['State']}"

    # the stale revision 1 must NOT have been mutated in place
    rev1_after = msk.describe_configuration_revision(Arn=config_arn, Revision=1)
    rev1_after_props = _parse_props(rev1_after["ServerProperties"])
    assert rev1_after_props == rev1_props, (
        f"stale revision 1 was mutated by concurrent updates: {rev1_props} -> {rev1_after_props}"
    )
    assert rev1_after["Revision"] == 1

    for rev in ok_revs:
        got = msk.describe_configuration_revision(Arn=config_arn, Revision=rev)
        assert got["Revision"] == rev, f"revision {rev} readback returned {got['Revision']}"

    # overly-permissive guard: unknown revision must be refused (400), not clamped
    code, status, message = _fail_info(
        lambda: msk.describe_configuration_revision(
            Arn=config_arn, Revision=expected_latest + 100
        )
    )
    assert code == "BadRequestException", (
        f"unknown configuration revision must be BadRequestException, got {code} (HTTP {status})"
    )
    assert status == 400, f"expected HTTP 400 for unknown revision, got {status}"
    assert message == _MISSING_ARN_MESSAGE, f"unexpected message: {message!r}"

    # overly-permissive guard: update of a nonexistent configuration -> 400, not 404/create
    prefix = ":".join(config_arn.split(":")[:5])
    ghost_arn = f"{prefix}:configuration/{ctx.unique_name('nx-config-')}/{uuid.uuid4()}-2"
    code2, status2, message2 = _fail_info(
        lambda: msk.update_configuration(
            Arn=ghost_arn, ServerProperties=b"auto.create.topics.enable=true\n"
        )
    )
    assert code2 == "BadRequestException", (
        f"UpdateConfiguration on missing configuration must be BadRequestException, "
        f"got {code2} (HTTP {status2})"
    )
    assert status2 == 400, f"expected HTTP 400, got {status2}"
    assert message2 == _MISSING_ARN_MESSAGE, f"unexpected message: {message2!r}"

    ghost_code, _, ghost_message = _fail_info(lambda: msk.describe_configuration(Arn=ghost_arn))
    assert ghost_code == "BadRequestException", (
        f"DescribeConfiguration on ghost configuration must be BadRequestException, got {ghost_code}"
    )
    assert ghost_message == _MISSING_ARN_MESSAGE, f"unexpected message: {ghost_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

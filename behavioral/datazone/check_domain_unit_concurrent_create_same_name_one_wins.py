"""domain-unit-concurrent-create-same-name-one-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "domain-unit-concurrent-create-same-name-one-wins"
GROUP = "concurrency"
SERVICES = ["datazone"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of five concurrent CreateDomainUnit calls for one name under one parent, exactly one succeeds, four
    fail with ConflictException, and the parent lists exactly one unit of that name, the winner's."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    root_id = domain["rootDomainUnitId"]
    name = ctx.unique_name("sim2real-dz-race-")

    racer_count = 5

    def _race(_i):
        try:
            resp = dz.create_domain_unit(
                domainIdentifier=domain["id"], name=name, parentDomainUnitIdentifier=root_id
            )
            return ("ok", resp["id"])
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", exc.response["Error"]["Code"])
            raise

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_race, range(racer_count)))

    successes = [r for kind, r in results if kind == "ok"]
    errors = [r for kind, r in results if kind == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {successes}"
    assert len(errors) == racer_count - 1, f"expected {racer_count - 1} losers, got {len(errors)}"
    # message varies: a loser gets either "Conflict with domainUnit <winner id>" or a storage
    # transaction-cancelled message whose reason list depends on how the racers interleaved.
    assert all(code == "ConflictException" for code in errors), f"expected ConflictException for every loser, got {errors}"

    winner_id = successes[0]
    ctx.on_cleanup(
        _safe(lambda: dz.delete_domain_unit(domainIdentifier=domain["id"], identifier=winner_id))
    )

    listed = dz.list_domain_units_for_parent(
        domainIdentifier=domain["id"], parentDomainUnitIdentifier=root_id
    )["items"]
    matches = [item for item in listed if item["name"] == name]
    assert len(matches) == 1, f"expected exactly 1 domain unit named {name!r} under root, got {matches}"
    assert matches[0]["id"] == winner_id, f"expected the listed unit to be the winner {winner_id}, got {matches[0]['id']}"


# ===== helpers =====
def _safe(fn, deadline_s=60.0):
    """Teardown: a resource already gone is fine; ConflictException (a dependent resource is still
    being released) is retried to a deadline; every other error raises."""
    def _wrapped():
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + deadline_s
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("ResourceNotFoundException", "NoSuchEntity"):
                    return
                if code != "ConflictException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _create_domain(ctx):
    dz = ctx.client("datazone")
    role_arn = _create_domain_execution_role(ctx)
    name = ctx.unique_name("sim2real-dz-domain-")
    created = _create_domain_call(dz, name, role_arn)
    domain_id = created["id"]
    ctx.on_cleanup(
        _safe(lambda: dz.delete_domain(identifier=domain_id, cascadeDelete=True))
    )
    return _wait_domain_available(ctx, domain_id)


def _create_domain_execution_role(ctx):

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dz-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "datazone.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetContext"],
            }
        ],
    }
    role = _create_role_with_retry(iam, role_name, trust_policy, tags=[{"Key": "sim2real-check", "Value": CHECK}])
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_role_with_retry(iam, role_name, trust_policy, timeout_s=60.0, tags=None):
    import json

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=tags or [])
        except Exception as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _create_domain_call(dz, name, role_arn, timeout_s=60.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return dz.create_domain(name=name, domainExecutionRole=role_arn, tags={"sim2real-check": CHECK})
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _wait_domain_available(ctx, domain_id, timeout_s=900.0):
    dz = ctx.client("datazone")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = dz.get_domain(identifier=domain_id)
        last = resp
        if resp["status"] == "AVAILABLE":
            return resp
        if resp["status"] == "CREATION_FAILED":
            raise AssertionError(f"domain {domain_id} creation failed: {resp}")
        time.sleep(5)
    raise AssertionError(f"domain {domain_id} did not become AVAILABLE in time: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

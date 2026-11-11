"""domain-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcases"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain rejects a name already used by another domain with ConflictException,
    leaving exactly one domain with that name, while creating a domain with a distinct
    unique name still succeeds."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    name = cc.get_domain(domainId=domain_id)["name"]

    error = _client_error(lambda: cc.create_domain(name=name))
    assert error.get("Code") == "ConflictException", f"expected ConflictException, got {error.get('Code')!r}"
    expected_message = f"Domain name already exists for account: {ctx.account}"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    domains = _all_domains(cc)
    matching = [d for d in domains if d["name"] == name]
    assert len(matching) == 1, f"expected exactly one domain named {name!r}, got {matching}"
    assert matching[0]["domainId"] == domain_id, (
        f"expected the surviving domain named {name!r} to be {domain_id!r}, "
        f"got {matching[0]['domainId']!r}"
    )

    other_domain_id = _create_active_domain(ctx)
    other_name = cc.get_domain(domainId=other_domain_id)["name"]
    assert other_name != name, f"expected a distinct name, got {other_name!r} == {name!r}"
    assert other_domain_id != domain_id, (
        f"expected a distinct domainId, got {other_domain_id!r} == {domain_id!r}"
    )


def _all_domains(cc) -> list[dict]:
    """Every page of ListDomains; the account can hold more domains than one page."""
    out, token = [], None
    while True:
        page = cc.list_domains(**({"nextToken": token} if token else {}))
        out.extend(page.get("domains", []))
        token = page.get("nextToken")
        if not token:
            return out


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a ConflictException, but the call SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_domain(ctx, domain_id):
    cc = ctx.client("connectcases")
    for _ in range(5):
        try:
            cc.delete_domain(domainId=domain_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConflictException":
                raise
            time.sleep(3.0)
    cc.delete_domain(domainId=domain_id)


def _create_active_domain(ctx):
    cc = ctx.client("connectcases")
    name = ctx.unique_name("sim2real-cc-domain-")
    created = cc.create_domain(name=name)
    domain_id = created["domainId"]
    ctx.on_cleanup(lambda: _delete_domain(ctx, domain_id))
    cc.tag_resource(arn=created["domainArn"], tags={"Owner": "behavioral"})
    status = _poll_until(
        lambda: cc.get_domain(domainId=domain_id)["domainStatus"],
        lambda s: s != "CreationInProgress",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "Active", f"domain reached terminal status {status!r}, expected Active"
    return domain_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

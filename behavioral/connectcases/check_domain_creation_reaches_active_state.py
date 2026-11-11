"""domain-creation-reaches-active-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-creation-reaches-active-state"
GROUP = "state"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created Cases domain transitions from CreationInProgress to Active and is
    listable via ListDomains with a matching ARN and name; once deleted it is gone from both
    GetDomain and ListDomains and no longer accepts mutations."""
    cc = ctx.client("connectcases")
    name = ctx.unique_name("sim2real-cc-domain-")
    create_resp = cc.create_domain(name=name)
    domain_id = create_resp["domainId"]
    domain_arn = create_resp["domainArn"]
    ctx.on_cleanup(lambda: _delete_domain(ctx, domain_id))

    status = _poll_until(
        lambda: cc.get_domain(domainId=domain_id)["domainStatus"],
        lambda s: s != "CreationInProgress",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "Active", f"domain reached terminal status {status!r}, expected Active"

    got = cc.get_domain(domainId=domain_id)
    assert got["domainId"] == domain_id, f"expected domainId {domain_id!r}, got {got['domainId']!r}"
    assert got["domainArn"] == domain_arn, f"expected domainArn {domain_arn!r}, got {got['domainArn']!r}"
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"

    domains = _all_domains(cc)
    matching = [d for d in domains if d["domainId"] == domain_id]
    assert len(matching) == 1, f"expected exactly one listed domain, got {matching}"
    assert matching[0]["name"] == name, f"expected listed name {name!r}, got {matching[0]['name']!r}"
    assert matching[0]["domainArn"] == domain_arn, (
        f"expected listed domainArn {domain_arn!r}, got {matching[0]['domainArn']!r}"
    )

    cc.delete_domain(domainId=domain_id)

    remaining_ids = _poll_until(
        lambda: {d["domainId"] for d in _all_domains(cc)},
        lambda ids: domain_id not in ids,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert domain_id not in remaining_ids, f"deleted domain {domain_id!r} still present in ListDomains"

    # GetDomain can still read the deleted domain for a few seconds after it leaves ListDomains.
    error = _poll_until(
        lambda: _get_domain_error(cc, domain_id),
        lambda err: err is not None,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {error.get('Code')!r}"
    )
    assert error.get("Message") == "Requested resource not found.", (
        f"expected GetDomain message 'Requested resource not found.' after delete, got {error.get('Message')!r}"
    )

    mutate_error = _client_error(
        lambda: cc.create_field(domainId=domain_id, name=ctx.unique_name("sim2real-cc-field-"), type="Text")
    )
    assert mutate_error.get("Code") == "ResourceNotFoundException", (
        f"expected mutation on deleted domain to fail with ResourceNotFoundException, "
        f"got {mutate_error.get('Code')!r}"
    )
    assert mutate_error.get("Message") == "Requested resource not found.", (
        f"expected CreateField message 'Requested resource not found.' on a deleted domain, "
        f"got {mutate_error.get('Message')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _get_domain_error(cc, domain_id):
    """GetDomain's botocore Error dict, or None while the domain still reads."""
    try:
        cc.get_domain(domainId=domain_id)
    except ClientError as err:
        return err.response.get("Error", {})
    return None


def _delete_domain(ctx, domain_id):
    cc = ctx.client("connectcases")
    for _ in range(5):
        try:
            cc.delete_domain(domainId=domain_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            time.sleep(3.0)
    cc.delete_domain(domainId=domain_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

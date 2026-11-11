"""domain-entry-crud-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "domain-entry-crud-lifecycle"
GROUP = "state"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomainEntry/UpdateDomainEntry/DeleteDomainEntry mutate the domain's DNS zone in place."""
    ls = _domain_client(ctx)
    domain_name = f"{ctx.unique_name('sim2real-ls-dom-')}.com"

    ls.create_domain(domainName=domain_name)
    ctx.on_cleanup(lambda: ls.delete_domain(domainName=domain_name))

    entry = {
        "name": f"www.{domain_name}",
        "type": "A",
        "target": "192.0.2.1",
        "isAlias": False,
    }
    ls.create_domain_entry(domainName=domain_name, domainEntry=entry)
    domain = ls.get_domain(domainName=domain_name)["domain"]
    created = _find_entry(domain, entry["name"], "A")
    assert created is not None, "created domain entry not found in zone after CreateDomainEntry"
    assert created["target"] == "192.0.2.1", f"expected target 192.0.2.1, got {created['target']!r}"
    entry_id = created["id"]

    updated_entry = dict(entry, id=entry_id, target="192.0.2.2")
    ls.update_domain_entry(domainName=domain_name, domainEntry=updated_entry)
    domain = ls.get_domain(domainName=domain_name)["domain"]
    updated = _find_entry(domain, entry["name"], "A")
    assert updated is not None, "updated domain entry not found in zone after UpdateDomainEntry"
    assert updated["target"] == "192.0.2.2", f"expected target 192.0.2.2, got {updated['target']!r}"

    ls.delete_domain_entry(domainName=domain_name, domainEntry=updated_entry)
    domain = ls.get_domain(domainName=domain_name)["domain"]
    assert _find_entry(domain, entry["name"], "A") is None, "domain entry still present after delete"

    try:
        ls.delete_domain_entry(domainName=domain_name, domainEntry=updated_entry)
    except ls.exceptions.OperationFailureException as exc:
        expected = (
            "Input error: No such domain record found in this domain for this "
            "name/type/target combination."
        )
        assert exc.response["Error"]["Message"] == expected, (
            f"expected a 'no such domain record' refusal, got {exc}"
        )
    else:
        raise AssertionError(
            "re-deleting an already-deleted domain entry did not raise OperationFailureException"
        )


def _domain_client(ctx):
    """Domain and distribution APIs are only available in the us-east-1 Region; ctx.client()'s
    region override pins the client to it while keeping the runner's endpoint/credential wiring."""
    return ctx.client("lightsail", region="us-east-1")


def _find_entry(domain, name, entry_type):
    for e in domain.get("domainEntries", []):
        if e.get("name") == name and e.get("type") == entry_type:
            return e
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

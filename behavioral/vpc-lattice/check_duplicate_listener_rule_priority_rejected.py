"""duplicate-listener-rule-priority-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-listener-rule-priority-rejected"
GROUP = 'rule-priority-rejected'
SERVICES = ['vpc-lattice']

_TAKEN = 10
_FREE = 20


def _error(fn):
    """The AWS (code, message) fn() raised; raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        "the call SUCCEEDED where real AWS refuses it — the guard under test is absent"
    )


def _all(fn, key, **kw):
    out, token = [], None
    while True:
        page = fn(**kw, nextToken=token) if token else fn(**kw)
        out.extend(page.get(key, []))
        token = page.get("nextToken")
        if not token:
            return out


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CreateRule at a priority a listener rule already holds fails with ConflictException
    "Rule with priority <n> already exist!" and leaves only the incumbent rule at that
    priority, while a rule at a free priority is created.
    """
    vl = ctx.client("vpc-lattice")
    kv = {"sim2real": "vpc-lattice-rule-priority"}

    svc = vl.create_service(name=ctx.unique_name("sim2real-latt-svc-"), authType="NONE", tags=kv)
    ctx.on_cleanup(lambda i=svc["id"]: vl.delete_service(serviceIdentifier=i))

    # A service is born CREATE_IN_PROGRESS and Lattice refuses every mutation until it settles, so
    # waiting here is what makes the teardown above able to run at all.
    deadline = time.time() + 300
    while True:
        svc_status = vl.get_service(serviceIdentifier=svc["id"])["status"]
        if svc_status == "ACTIVE":
            break
        assert svc_status == "CREATE_IN_PROGRESS" and time.time() < deadline, (
            f"service {svc['id']} never reached ACTIVE: status={svc_status!r}"
        )
        time.sleep(3)

    listener = vl.create_listener(
        serviceIdentifier=svc["id"], name=ctx.unique_name("sim2real-latt-ln-"),
        protocol="HTTP", port=80, defaultAction={"fixedResponse": {"statusCode": 404}}, tags=kv,
    )
    ctx.on_cleanup(
        lambda s=svc["id"], i=listener["id"]: vl.delete_listener(
            serviceIdentifier=s, listenerIdentifier=i
        )
    )

    incumbent = vl.create_rule(
        serviceIdentifier=svc["id"], listenerIdentifier=listener["id"],
        name=ctx.unique_name("sim2real-latt-rule-"), priority=_TAKEN,
        match={"httpMatch": {"pathMatch": {"match": {"prefix": "/incumbent"}}}},
        action={"fixedResponse": {"statusCode": 404}}, tags=kv,
    )
    ctx.on_cleanup(
        lambda s=svc["id"], l=listener["id"], i=incumbent["id"]: vl.delete_rule(
            serviceIdentifier=s, listenerIdentifier=l, ruleIdentifier=i
        )
    )
    assert incumbent["priority"] == _TAKEN, (
        f"the first rule was created at priority {incumbent['priority']!r}, not the requested "
        f"{_TAKEN} — the rest of this check would be probing the wrong priority"
    )

    error = _error(
        lambda: vl.create_rule(
            serviceIdentifier=svc["id"], listenerIdentifier=listener["id"],
            name=ctx.unique_name("sim2real-latt-dup-"), priority=_TAKEN,
            match={"httpMatch": {"pathMatch": {"match": {"prefix": "/duplicate"}}}},
            action={"fixedResponse": {"statusCode": 404}}, tags=kv,
        )
    )
    expected_error = ("ConflictException", f"Rule with priority {_TAKEN} already exist!")
    assert error == expected_error, (
        f"a second rule at the occupied priority {_TAKEN} raised {error!r}; "
        f"real AWS raises {expected_error!r}"
    )

    # The refused create must have added nothing: exactly the incumbent, still at its priority.
    rules = _all(
        vl.list_rules, "items", serviceIdentifier=svc["id"], listenerIdentifier=listener["id"]
    )
    by_priority = {r["id"]: r["priority"] for r in rules if not r.get("isDefault")}
    assert by_priority == {incumbent["id"]: _TAKEN}, (
        f"after the refused create the listener holds {by_priority!r}; it must hold only the "
        f"incumbent {incumbent['id']!r} at priority {_TAKEN}"
    )

    # Positive control: the same shape of rule at a free priority is accepted, so the refusal
    # above was the priority collision and not a listener that rejects every rule.
    spare = vl.create_rule(
        serviceIdentifier=svc["id"], listenerIdentifier=listener["id"],
        name=ctx.unique_name("sim2real-latt-rule-"), priority=_FREE,
        match={"httpMatch": {"pathMatch": {"match": {"prefix": "/duplicate"}}}},
        action={"fixedResponse": {"statusCode": 404}}, tags=kv,
    )
    ctx.on_cleanup(
        lambda s=svc["id"], l=listener["id"], i=spare["id"]: vl.delete_rule(
            serviceIdentifier=s, listenerIdentifier=l, ruleIdentifier=i
        )
    )
    assert spare["priority"] == _FREE, (
        f"the positive control landed at priority {spare['priority']!r}, not the requested {_FREE}"
    )

    final = {
        r["priority"]
        for r in _all(
            vl.list_rules, "items", serviceIdentifier=svc["id"], listenerIdentifier=listener["id"]
        )
        if not r.get("isDefault")
    }
    assert final == {_TAKEN, _FREE}, (
        f"the listener ended with priorities {sorted(final)!r}, expected exactly "
        f"{sorted({_TAKEN, _FREE})!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

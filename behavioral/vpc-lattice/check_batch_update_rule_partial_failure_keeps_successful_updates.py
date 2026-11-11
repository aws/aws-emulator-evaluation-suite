"""batch-update-rule-partial-failure-keeps-successful-updates."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-update-rule-partial-failure-keeps-successful-updates"
GROUP = 'batch-update-rule'
SERVICES = ['vpc-lattice']


@tags("concern:representation", "concern:negative-classes", "axis:rejection", "cap:c1", "plane:control")
def run(ctx) -> None:
    """BatchUpdateRule applies a real update beside a failing one from the same call, and a
    later GetRule -- not the batch response alone -- is what proves it took effect.
    """
    vl = ctx.client("vpc-lattice")
    kv = {"sim2real": "vpc-lattice-batch-update-rule"}

    svc = vl.create_service(name=ctx.unique_name("sim2real-latt-bur-"), authType="NONE", tags=kv)
    ctx.on_cleanup(lambda i=svc["id"]: vl.delete_service(serviceIdentifier=i))

    deadline = time.time() + 300
    while True:
        status = vl.get_service(serviceIdentifier=svc["id"])["status"]
        if status == "ACTIVE":
            break
        assert status == "CREATE_IN_PROGRESS" and time.time() < deadline, (
            f"service {svc['id']} never reached ACTIVE: status={status!r}"
        )
        time.sleep(3)

    listener = vl.create_listener(
        serviceIdentifier=svc["id"], name=ctx.unique_name("sim2real-latt-burl-"),
        protocol="HTTP", port=80, defaultAction={"fixedResponse": {"statusCode": 404}}, tags=kv,
    )
    ctx.on_cleanup(
        lambda s=svc["id"], i=listener["id"]: vl.delete_listener(serviceIdentifier=s, listenerIdentifier=i)
    )

    rule = vl.create_rule(
        serviceIdentifier=svc["id"], listenerIdentifier=listener["id"],
        name=ctx.unique_name("sim2real-latt-burr-"), priority=10,
        match={"httpMatch": {"pathMatch": {"match": {"prefix": "/a"}}}},
        action={"fixedResponse": {"statusCode": 404}}, tags=kv,
    )
    ctx.on_cleanup(
        lambda s=svc["id"], l=listener["id"], i=rule["id"]: vl.delete_rule(
            serviceIdentifier=s, listenerIdentifier=l, ruleIdentifier=i
        )
    )

    missing_id = "rule-0123456789abcdef0"
    result = vl.batch_update_rule(
        serviceIdentifier=svc["id"], listenerIdentifier=listener["id"],
        rules=[
            {"ruleIdentifier": rule["id"], "priority": 50},
            {"ruleIdentifier": missing_id, "priority": 60},
        ],
    )
    successful_ids = {r["id"] for r in result["successful"]}
    unsuccessful_ids = {r["ruleIdentifier"] for r in result["unsuccessful"]}
    assert successful_ids == {rule["id"]}, (
        f"BatchUpdateRule's successful list is {successful_ids!r}, expected only {rule['id']!r}"
    )
    assert unsuccessful_ids == {missing_id}, (
        f"BatchUpdateRule's unsuccessful list names {unsuccessful_ids!r}, expected {{{missing_id!r}}}"
    )

    settled = vl.get_rule(
        serviceIdentifier=svc["id"], listenerIdentifier=listener["id"], ruleIdentifier=rule["id"]
    )
    assert settled["priority"] == 50, (
        f"an independent GetRule after the batch reports priority {settled['priority']!r}; the "
        f"successful half of a partially-failed batch must still have taken effect (expected 50)"
    )

    # A batch whose result would collide two rules on one priority fails the WHOLE call instead
    # of partially applying it -- the opposite failure shape for the same operation.
    other = vl.create_rule(
        serviceIdentifier=svc["id"], listenerIdentifier=listener["id"],
        name=ctx.unique_name("sim2real-latt-burr2-"), priority=70,
        match={"httpMatch": {"pathMatch": {"match": {"prefix": "/b"}}}},
        action={"fixedResponse": {"statusCode": 404}}, tags=kv,
    )
    ctx.on_cleanup(
        lambda s=svc["id"], l=listener["id"], i=other["id"]: vl.delete_rule(
            serviceIdentifier=s, listenerIdentifier=l, ruleIdentifier=i
        )
    )

    try:
        vl.batch_update_rule(
            serviceIdentifier=svc["id"], listenerIdentifier=listener["id"],
            rules=[{"ruleIdentifier": other["id"], "priority": 50}],
        )
        raise AssertionError("a colliding BatchUpdateRule call unexpectedly succeeded")
    except ClientError as exc:
        error = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        expected_error = ("ConflictException", f"Rule with priority {other['priority']} already exist!")
        assert error == expected_error, f"a colliding batch raised {error!r}, expected {expected_error!r}"

    unmoved_rule = vl.get_rule(
        serviceIdentifier=svc["id"], listenerIdentifier=listener["id"], ruleIdentifier=rule["id"]
    )
    unmoved_other = vl.get_rule(
        serviceIdentifier=svc["id"], listenerIdentifier=listener["id"], ruleIdentifier=other["id"]
    )
    assert unmoved_rule["priority"] == 50 and unmoved_other["priority"] == 70, (
        f"after the refused batch, priorities are {unmoved_rule['priority']!r} and "
        f"{unmoved_other['priority']!r}; a rejected batch must change neither rule"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

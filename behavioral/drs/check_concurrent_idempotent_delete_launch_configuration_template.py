"""concurrent-idempotent-delete-launch-configuration-template."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-idempotent-delete-launch-configuration-template"
GROUP = "concurrency"
SERVICES = ["drs"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "requires:drs-initialized",
)
def run(ctx) -> None:
    """Two racing DeleteLaunchConfigurationTemplate calls on the same template either both
    succeed or one succeeds and the other gets ResourceNotFoundException; no other code appears,
    and the template is gone from an independent read after the race resolves.
    """
    drs = ctx.client("drs")

    created = drs.create_launch_configuration_template()["launchConfigurationTemplate"]
    lct_id = created["launchConfigurationTemplateID"]
    ctx.on_cleanup(lambda: _delete_lct(drs, lct_id))

    loser_messages = []

    def _race(_):
        try:
            drs.delete_launch_configuration_template(launchConfigurationTemplateID=lct_id)
            return "ok"
        except ClientError as exc:
            loser_messages.append(exc.response["Error"].get("Message"))
            return exc.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(_race, range(2)))

    assert outcomes.count("ok") >= 1, f"at least one concurrent delete must succeed, got {outcomes}"
    assert set(outcomes) <= {"ok", "ResourceNotFoundException"}, (
        "a concurrent delete race must resolve to either both succeeding (idempotent delete) or "
        f"the loser seeing ResourceNotFoundException -- never any other error, got {outcomes}"
    )
    not_found = f"Launch Configuration Template with Id: '{lct_id}' was not found"
    assert all(m == not_found for m in loser_messages), (
        f"a losing concurrent delete must answer {not_found!r}, got {loser_messages!r}"
    )

    remaining = drs.describe_launch_configuration_templates(
        launchConfigurationTemplateIDs=[lct_id]
    )["items"]
    assert remaining == [], f"the template must be gone after the race resolves, got {remaining!r}"


def _delete_lct(drs, lct_id: str) -> None:
    try:
        drs.delete_launch_configuration_template(launchConfigurationTemplateID=lct_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

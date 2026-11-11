"""usage-profile-empty-vs-absent-config-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "usage-profile-empty-vs-absent-config-preserved"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUsageProfile preserves an explicitly empty JobConfiguration or SessionConfiguration map
    ({}) as present-but-empty and an omitted one as absent, rather than normalizing both."""
    glue = ctx.client("glue")

    # Filler for the other map: workerType and numberOfWorkers are required together, and
    # arbitrary keys are silently dropped rather than round-tripped.
    worker_cfg = {
        "workerType": {"DefaultValue": "G.1X", "AllowedValues": ["G.1X", "G.2X"]},
        "numberOfWorkers": {"DefaultValue": "2", "MinValue": "1", "MaxValue": "10"},
    }
    resource_tags = {"sim2real-check": CHECK}

    name_session_empty = ctx.unique_name("sim2real-behav-profempty-sess-")
    name_session_absent = ctx.unique_name("sim2real-behav-profabsent-sess-")
    name_job_empty = ctx.unique_name("sim2real-behav-profempty-job-")
    name_job_absent = ctx.unique_name("sim2real-behav-profabsent-job-")

    glue.create_usage_profile(
        Name=name_session_empty,
        Configuration={"JobConfiguration": worker_cfg, "SessionConfiguration": {}},
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: glue.delete_usage_profile(Name=name_session_empty))

    glue.create_usage_profile(
        Name=name_session_absent,
        Configuration={"JobConfiguration": worker_cfg},
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: glue.delete_usage_profile(Name=name_session_absent))

    glue.create_usage_profile(
        Name=name_job_empty,
        Configuration={"SessionConfiguration": worker_cfg, "JobConfiguration": {}},
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: glue.delete_usage_profile(Name=name_job_empty))

    glue.create_usage_profile(
        Name=name_job_absent,
        Configuration={"SessionConfiguration": worker_cfg},
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: glue.delete_usage_profile(Name=name_job_absent))

    cfg_session_empty = glue.get_usage_profile(Name=name_session_empty)["Configuration"]
    cfg_session_absent = glue.get_usage_profile(Name=name_session_absent)["Configuration"]
    cfg_job_empty = glue.get_usage_profile(Name=name_job_empty)["Configuration"]
    cfg_job_absent = glue.get_usage_profile(Name=name_job_absent)["Configuration"]

    assert "SessionConfiguration" in cfg_session_empty, "explicitly empty SessionConfiguration was dropped entirely"
    assert cfg_session_empty["SessionConfiguration"] == {}, (
        f"explicitly empty SessionConfiguration was not preserved as {{}}: {cfg_session_empty['SessionConfiguration']!r}"
    )
    assert "SessionConfiguration" not in cfg_session_absent, (
        "an omitted SessionConfiguration was normalized into a present (possibly empty) map "
        f"instead of staying absent: {cfg_session_absent!r}"
    )

    assert "JobConfiguration" in cfg_job_empty, "explicitly empty JobConfiguration was dropped entirely"
    assert cfg_job_empty["JobConfiguration"] == {}, (
        f"explicitly empty JobConfiguration was not preserved as {{}}: {cfg_job_empty['JobConfiguration']!r}"
    )
    assert "JobConfiguration" not in cfg_job_absent, (
        "an omitted JobConfiguration was normalized into a present (possibly empty) map "
        f"instead of staying absent: {cfg_job_absent!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


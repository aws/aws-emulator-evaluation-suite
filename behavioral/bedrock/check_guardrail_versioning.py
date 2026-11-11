"""guardrail-versioning."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

_READY_TIMEOUT_S = 180


def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", _unique_name("gr-"))
    kwargs.setdefault("blockedInputMessaging", "Input blocked by guardrail.")
    kwargs.setdefault("blockedOutputsMessaging", "Output blocked by guardrail.")
    tags_kw = kwargs.pop("tags", [{"key": "sim2real", "value": "guardrail-versioning"}])
    resp = bc.create_guardrail(tags=tags_kw, **kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp


def _wait_ready(bc, gid, version=None):
    """Converge on a TERMINAL GuardrailStatus. CreateGuardrail/CreateGuardrailVersion are
    asynchronous -- calling CreateGuardrailVersion while the DRAFT is still CREATING is a race,
    not a guarantee."""
    kw = {"guardrailIdentifier": gid}
    if version is not None:
        kw["guardrailVersion"] = version
    deadline = time.monotonic() + _READY_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        status = bc.get_guardrail(**kw)["status"]
        if status in ("READY", "FAILED"):
            break
        time.sleep(3)
    assert status == "READY", (
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY "
        f"within {_READY_TIMEOUT_S}s; last status={status!r}"
    )


CHECK = "guardrail-versioning"
GROUP = 'guardrails'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGuardrailVersion on a fresh DRAFT numbers the first version "1"; the numbered
    version reaches READY and GetGuardrail by that version returns it -- through an independent
    read, not the mutating call's own response."""
    bc = ctx.client("bedrock")
    create_resp = _create_guardrail(bc, ctx,
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": "sim2real-version-topic",
                    "definition": "Versioning test topic",
                    "type": "DENY",
                }
            ]
        })
    gid = create_resp["guardrailId"]
    _wait_ready(bc, gid)

    ver_resp = bc.create_guardrail_version(guardrailIdentifier=gid)
    version = ver_resp.get("version")
    assert version is not None, "CreateGuardrailVersion returned no version"
    assert version == "1", (
        f"the first CreateGuardrailVersion on a fresh guardrail must number the version '1'; "
        f"got {version!r}"
    )
    _wait_ready(bc, gid, version)

    get_resp = bc.get_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    assert get_resp["version"] == version, (
        f"GetGuardrail(guardrailVersion={version!r}) must echo the requested version; "
        f"got {get_resp.get('version')!r}"
    )
    assert get_resp["status"] == "READY", (
        f"GetGuardrail(guardrailVersion={version!r}) must report the version's own terminal "
        f"status, not the DRAFT's; got {get_resp.get('status')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

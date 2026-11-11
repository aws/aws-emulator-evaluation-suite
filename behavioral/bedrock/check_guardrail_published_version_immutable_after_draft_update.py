"""guardrail-published-version-immutable-after-draft-update."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guardrail-published-version-immutable-after-draft-update"
GROUP = 'guardrails'
SERVICES = ['bedrock']


_BLOCKED_IN = "sim2real-blocked-input-4a13"
_BLOCKED_OUT = "sim2real-blocked-output-4a13"
_READY_TIMEOUT_S = 180

_TOPIC_NAME = "sim2real-immutability-topic"
_DEF_V1 = (
    "ALPHA definition: requests for the alpha build of the internal reporting tool, including "
    "download links and release notes."
)
_DEF_DRAFT = (
    "BETA definition: requests for the beta build of the internal reporting tool, including "
    "download links and release notes."
)
_WORD = "zorblatt"

# A published version carries the description passed to CreateGuardrailVersion, not a snapshot of
# the guardrail's own description.
_VERSION_NOTE = "sim2real immutability: v1 snapshot note"


def _poll(fn, pred, *, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _guardrail_status(bc, gid, version=None):
    kw = {"guardrailIdentifier": gid}
    if version is not None:
        kw["guardrailVersion"] = version
    try:
        return bc.get_guardrail(**kw)["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "ABSENT"
        raise


def _wait_ready(bc, gid, version=None):
    """Wait for a terminal GuardrailStatus (READY or FAILED) and require READY."""
    status = _poll(
        lambda: _guardrail_status(bc, gid, version),
        lambda s: s in ("READY", "FAILED"),
        timeout_s=_READY_TIMEOUT_S,
    )
    assert status == "READY", (
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY; "
        f"last status={status!r}"
    )


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-gr-"))
    kwargs.setdefault("blockedInputMessaging", _BLOCKED_IN)
    kwargs.setdefault("blockedOutputsMessaging", _BLOCKED_OUT)
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp


def _publish_version(bc, ctx, gid):
    """CreateGuardrailVersion freezes the current DRAFT.

    Cleanups run LIFO, so the version is deleted before the guardrail."""
    version = bc.create_guardrail_version(
        guardrailIdentifier=gid, description=_VERSION_NOTE
    )["version"]
    ctx.on_cleanup(
        lambda: bc.delete_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    )
    _wait_ready(bc, gid, version)
    return version


def _topic_defs(resp):
    """{topic name: definition} from a GetGuardrail response."""
    topics = (resp.get("topicPolicy") or {}).get("topics") or []
    return {t.get("name"): t.get("definition") for t in topics}


def _words(resp):
    return [w.get("text") for w in (resp.get("wordPolicy") or {}).get("words") or []]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A published guardrail version is immutable: a DRAFT update changes only the DRAFT.

    Callers pin numbered versions so a policy edit cannot change enforcement; the update both edits
    a topic and adds a wordPolicy, and the published version must reflect neither.
    """
    bc = ctx.client("bedrock")

    # CreateGuardrailResponse does not echo `name`, and UpdateGuardrail requires it, so hold it.
    name = ctx.unique_name("sim2real-behav-gr-")

    created = _create_guardrail(
        bc,
        ctx,
        name=name,
        description="sim2real immutability: v1 config",
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": _TOPIC_NAME,
                    "definition": _DEF_V1,
                    "examples": ["Where do I download the alpha build?"],
                    "type": "DENY",
                }
            ]
        },
    )
    gid = created["guardrailId"]
    assert created["version"] == "DRAFT", (
        f"CreateGuardrailResponse.version is modeled as GuardrailDraftVersion (^DRAFT$); "
        f"got {created['version']!r}"
    )
    _wait_ready(bc, gid)

    version = _publish_version(bc, ctx, gid)
    assert version != "DRAFT", (
        f"CreateGuardrailVersion must return a numbered version, not DRAFT; got {version!r}"
    )

    # Update the DRAFT: change the topic definition AND add a policy type that v1 does not have.
    bc.update_guardrail(
        guardrailIdentifier=gid,
        name=name,
        blockedInputMessaging=_BLOCKED_IN,
        blockedOutputsMessaging=_BLOCKED_OUT,
        description="sim2real immutability: draft config",
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": _TOPIC_NAME,
                    "definition": _DEF_DRAFT,
                    "examples": ["Where do I download the beta build?"],
                    "type": "DENY",
                }
            ]
        },
        wordPolicyConfig={"wordsConfig": [{"text": _WORD}]},
    )
    _wait_ready(bc, gid)

    draft = bc.get_guardrail(guardrailIdentifier=gid, guardrailVersion="DRAFT")
    pinned = bc.get_guardrail(guardrailIdentifier=gid, guardrailVersion=version)

    # The DRAFT moved.
    assert _topic_defs(draft).get(_TOPIC_NAME) == _DEF_DRAFT, (
        f"DRAFT must reflect the update; topic definitions={_topic_defs(draft)!r}"
    )
    assert _words(draft) == [_WORD], (
        f"DRAFT must carry the newly added wordPolicy [{_WORD!r}]; got {_words(draft)!r}"
    )
    assert draft["description"] == "sim2real immutability: draft config", (
        f"DRAFT description must reflect the update; got {draft['description']!r}"
    )

    # The published version did not.
    assert _topic_defs(pinned).get(_TOPIC_NAME) == _DEF_V1, (
        f"published version {version} must still hold the pre-update topic definition; "
        f"got {_topic_defs(pinned)!r} (an emulator ignoring guardrailVersion on read returns the "
        f"DRAFT config here)"
    )
    assert _words(pinned) == [], (
        f"published version {version} predates the wordPolicy and must not have one; "
        f"got {_words(pinned)!r}"
    )
    # A version's `description` is the CreateGuardrailVersion note (omitted when none was given),
    # not the guardrail's description; it stays frozen while the DRAFT description moves.
    assert pinned["description"] == _VERSION_NOTE, (
        f"published version {version} must carry the description given at publication "
        f"({_VERSION_NOTE!r}); got {pinned.get('description')!r}"
    )
    assert pinned["description"] != draft["description"], (
        f"the version note and the DRAFT description are separate fields and must not converge; "
        f"both were {pinned['description']!r}"
    )
    assert pinned["version"] == version, (
        f"GetGuardrail must echo the requested version {version!r}; got {pinned['version']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

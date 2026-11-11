"""create-meeting-returns-full-meeting-fields."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-meeting-returns-full-meeting-fields"
GROUP = "lifecycle"
SERVICES = ["chime-sdk-meetings"]

_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# Confirmed against real AWS: only these two MediaPlacement URLs embed the meeting
# id in their path (/calls/<id>, /control/<id>); AudioHostUrl uses an opaque host
# hash and EventIngestionUrl is a generic per-region endpoint, so they are checked
# for presence only, not for id embedding.
_ID_EMBEDDING_PLACEMENT_FIELDS = ("AudioFallbackUrl", "SignalingUrl")
_PLACEMENT_FIELDS = ("AudioHostUrl", "AudioFallbackUrl", "SignalingUrl", "EventIngestionUrl")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMeeting returns a Meeting whose semantic fields -- including the ARN's
    encoded account/region/meeting-id and every non-deprecated MediaPlacement URL --
    survive a GetMeeting round-trip."""
    chime = ctx.client("chime-sdk-meetings")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    external_meeting_id = ctx.unique_name("sim2real-ext-")
    token = ctx.unique_name("sim2real-token-")

    created = chime.create_meeting(
        ClientRequestToken=token,
        MediaRegion="us-east-1",  # a required Meeting param (media placement region), not ctx.region
        ExternalMeetingId=external_meeting_id,
    )["Meeting"]
    meeting_id = created["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    assert _GUID_RE.match(meeting_id), f"MeetingId is not a GUID: {meeting_id!r}"
    assert created["ExternalMeetingId"] == external_meeting_id, (
        f"expected ExternalMeetingId {external_meeting_id!r}, got {created['ExternalMeetingId']!r}"
    )
    assert created["MediaRegion"] == "us-east-1", (
        f"expected MediaRegion 'us-east-1', got {created['MediaRegion']!r}"
    )
    expected_arn = f"arn:aws:chime:{ctx.region}:{account_id}:meeting/{meeting_id}"
    assert created["MeetingArn"] == expected_arn, (
        f"expected MeetingArn {expected_arn!r} (region+account+meeting-id encoded), "
        f"got {created['MeetingArn']!r}"
    )

    placement = created["MediaPlacement"]
    for field in _PLACEMENT_FIELDS:
        assert placement.get(field), f"MediaPlacement.{field} is empty: {placement!r}"
    for field in _ID_EMBEDDING_PLACEMENT_FIELDS:
        assert meeting_id in placement[field], (
            f"MediaPlacement.{field} {placement[field]!r} does not embed "
            f"this meeting's id {meeting_id!r}"
        )

    fetched = chime.get_meeting(MeetingId=meeting_id)["Meeting"]
    assert fetched["MeetingId"] == meeting_id, (
        f"GetMeeting returned MeetingId {fetched['MeetingId']!r}, expected {meeting_id!r}"
    )
    assert fetched["ExternalMeetingId"] == external_meeting_id, (
        f"GetMeeting ExternalMeetingId {fetched['ExternalMeetingId']!r} != {external_meeting_id!r}"
    )
    assert fetched["MediaRegion"] == "us-east-1", (
        f"GetMeeting MediaRegion {fetched['MediaRegion']!r} != 'us-east-1'"
    )
    assert fetched["MeetingArn"] == created["MeetingArn"], (
        f"GetMeeting MeetingArn {fetched['MeetingArn']!r} != CreateMeeting's {created['MeetingArn']!r}"
    )
    fetched_placement = fetched["MediaPlacement"]
    for field in _PLACEMENT_FIELDS:
        assert fetched_placement.get(field) == placement[field], (
            f"GetMeeting MediaPlacement.{field} {fetched_placement.get(field)!r} != "
            f"CreateMeeting's {placement[field]!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

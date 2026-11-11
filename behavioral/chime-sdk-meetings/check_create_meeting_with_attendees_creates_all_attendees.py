"""create-meeting-with-attendees-creates-all-attendees."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-meeting-with-attendees-creates-all-attendees"
GROUP = "e2e"
SERVICES = ["chime-sdk-meetings"]


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMeetingWithAttendees creates the meeting and three distinct attendees, all listed by
    ListAttendees; a tag, a transcription start/stop and a capability update then take effect, and
    after DeleteMeeting, GetMeeting and ListAttendees fail with NotFoundException "The meeting has ended"."""
    chime = ctx.client("chime-sdk-meetings")
    external_ids = [ctx.unique_name(f"sim2real-cma-{i}-") for i in range(3)]

    resp = chime.create_meeting_with_attendees(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        # MediaRegion is the meeting's media-plane pin, independent of the API endpoint region
        # the harness targets -- any supported Chime SDK media region is a valid, arbitrary choice.
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
        Attendees=[{"ExternalUserId": eid} for eid in external_ids],
    )
    meeting_id = resp["Meeting"]["MeetingId"]
    meeting_arn = resp["Meeting"]["MeetingArn"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    assert resp.get("Errors", []) == [], f"expected no per-attendee errors, got {resp.get('Errors')!r}"
    attendees = resp["Attendees"]
    assert len(attendees) == 3, f"expected 3 attendees, got {len(attendees)}"
    returned_ext_ids = {a["ExternalUserId"] for a in attendees}
    assert returned_ext_ids == set(external_ids), f"expected {set(external_ids)!r}, got {returned_ext_ids!r}"
    attendee_ids = {a["AttendeeId"] for a in attendees}
    assert len(attendee_ids) == 3, f"expected 3 distinct AttendeeIds, got {attendee_ids!r}"
    for a in attendees:
        assert a["JoinToken"], f"attendee {a['AttendeeId']} missing JoinToken"

    listed = chime.list_attendees(MeetingId=meeting_id)["Attendees"]
    listed_ext_ids = {a["ExternalUserId"] for a in listed}
    assert listed_ext_ids == set(external_ids), f"expected {set(external_ids)!r}, got {listed_ext_ids!r}"

    # Stage 2: tag the freshly created meeting resource and confirm the tag round-trips.
    chime.tag_resource(ResourceARN=meeting_arn, Tags=[{"Key": "sim2real-stage", "Value": "e2e"}])
    tag_map = {t["Key"]: t["Value"] for t in chime.list_tags_for_resource(ResourceARN=meeting_arn)["Tags"]}
    assert tag_map.get("sim2real-stage") == "e2e", f"got tags {tag_map!r}"

    # Stage 3: start and stop live transcription on the same meeting.
    chime.start_meeting_transcription(
        MeetingId=meeting_id,
        TranscriptionConfiguration={"EngineTranscribeSettings": {"LanguageCode": "en-US"}},
    )
    stop_resp = chime.stop_meeting_transcription(MeetingId=meeting_id)
    assert stop_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"got {stop_resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    # Stage 4: update one attendee's capabilities and confirm the change is visible.
    target = attendees[0]
    new_caps = {"Audio": "Receive", "Video": "SendReceive", "Content": "SendReceive"}
    chime.update_attendee_capabilities(
        MeetingId=meeting_id, AttendeeId=target["AttendeeId"], Capabilities=new_caps
    )
    updated = chime.get_attendee(MeetingId=meeting_id, AttendeeId=target["AttendeeId"])["Attendee"]
    assert updated["Capabilities"] == new_caps, f"got {updated['Capabilities']!r}"

    # Stage 5: tear down and confirm the meeting-scoped views are gone.
    chime.delete_meeting(MeetingId=meeting_id)
    get_code, get_message = _client_error(lambda: chime.get_meeting(MeetingId=meeting_id))
    assert get_code == "NotFoundException", f"got {get_code!r}"
    assert get_message == "The meeting has ended", f"got message={get_message!r}"
    list_code, list_message = _client_error(lambda: chime.list_attendees(MeetingId=meeting_id))
    assert list_code == "NotFoundException", f"got {list_code!r}"
    assert list_message == "The meeting has ended", f"got message={list_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

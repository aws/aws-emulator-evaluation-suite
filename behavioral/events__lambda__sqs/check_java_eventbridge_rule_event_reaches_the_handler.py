"""java-eventbridge-rule-event-reaches-the-handler."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-eventbridge-rule-event-reaches-the-handler"
GROUP = "eventing"
SERVICES = ["events", "lambda", "sqs"]

# com.amazonaws.services.lambda.runtime.RequestHandler<Map<String,Object>, Void>: an EventBridge
# rule target's event reaches the handler as a generic Map (no ScheduledEvent/custom POJO), and
# the handler relays the whole matched event as JSON to an SQS queue the check owns, signing the
# SendMessage call itself (no AWS SDK bundled) so the check can verify the PutEvents entry
# survived unchanged to the Java runtime.
_SHA256 = "bbe62103061e14721a909d1b84636ae36d4547fa0a557a2760afcf79be06fb67"

_B64 = (  # @@GENERATED@@ probe/EventBridgeHandler.class
    "yv66vgAAAEEBhQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWBwAIAQAXamF2YS9sYW5n"
    "L1N0cmluZ0J1aWxkZXIKAAcAAwgACwEABCUwMngKAA0ADgcADwwAEAARAQAOamF2YS9sYW5nL0J5dGUBAAd2YWx1ZU9mAQAT"
    "KEIpTGphdmEvbGFuZy9CeXRlOwoAEwAUBwAVDAAWABcBABBqYXZhL2xhbmcvU3RyaW5nAQAGZm9ybWF0AQA5KExqYXZhL2xh"
    "bmcvU3RyaW5nO1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9TdHJpbmc7CgAHABkMABoAGwEABmFwcGVuZAEALShM"
    "amF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwoABwAdDAAeAB8BAAh0b1N0cmluZwEAFCgpTGph"
    "dmEvbGFuZy9TdHJpbmc7CAAhAQAKSG1hY1NIQTI1NgoAIwAkBwAlDAAmACcBABBqYXZheC9jcnlwdG8vTWFjAQALZ2V0SW5z"
    "dGFuY2UBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZheC9jcnlwdG8vTWFjOwcAKQEAH2phdmF4L2NyeXB0by9zcGVjL1Nl"
    "Y3JldEtleVNwZWMKACgAKwwABQAsAQAXKFtCTGphdmEvbGFuZy9TdHJpbmc7KVYKACMALgwALwAwAQAEaW5pdAEAFihMamF2"
    "YS9zZWN1cml0eS9LZXk7KVYJADIAMwcANAwANQA2AQAhamF2YS9uaW8vY2hhcnNldC9TdGFuZGFyZENoYXJzZXRzAQAFVVRG"
    "XzgBABpMamF2YS9uaW8vY2hhcnNldC9DaGFyc2V0OwoAEwA4DAA5ADoBAAhnZXRCeXRlcwEAHihMamF2YS9uaW8vY2hhcnNl"
    "dC9DaGFyc2V0OylbQgoAIwA8DAA9AD4BAAdkb0ZpbmFsAQAGKFtCKVtCCABAAQAHU0hBLTI1NgoAQgBDBwBEDAAmAEUBABtq"
    "YXZhL3NlY3VyaXR5L01lc3NhZ2VEaWdlc3QBADEoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3NlY3VyaXR5L01lc3NhZ2VE"
    "aWdlc3Q7CgBCAEcMAEgAPgEABmRpZ2VzdAoASgBLBwBMDABNAE4BABhwcm9iZS9FdmVudEJyaWRnZUhhbmRsZXIBAANoZXgB"
    "ABYoW0IpTGphdmEvbGFuZy9TdHJpbmc7CgAHAFAMABoAUQEAHChDKUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsKABMAUwwA"
    "VABVAQAGbGVuZ3RoAQADKClJCgATAFcMAFgAWQEABmNoYXJBdAEABChJKUMIAFsBAAJcIggAXQEAAlxcCABfAQACXG4IAGEB"
    "AAJccggAYwEAAlx0CABlAQAGXHUlMDR4CgBnAGgHAGkMABAAagEAEWphdmEvbGFuZy9JbnRlZ2VyAQAWKEkpTGphdmEvbGFu"
    "Zy9JbnRlZ2VyOwgAbAEABG51bGwHAG4BAA1qYXZhL3V0aWwvTWFwCwBtAHAMAHEAcgEACGVudHJ5U2V0AQARKClMamF2YS91"
    "dGlsL1NldDsLAHQAdQcAdgwAdwB4AQANamF2YS91dGlsL1NldAEACGl0ZXJhdG9yAQAWKClMamF2YS91dGlsL0l0ZXJhdG9y"
    "OwsAegB7BwB8DAB9AH4BABJqYXZhL3V0aWwvSXRlcmF0b3IBAAdoYXNOZXh0AQADKClaCwB6AIAMAIEAggEABG5leHQBABQo"
    "KUxqYXZhL2xhbmcvT2JqZWN0OwcAhAEAE2phdmEvdXRpbC9NYXAkRW50cnkLAIMAhgwAhwCCAQAGZ2V0S2V5CgBKAIkMAIoA"
    "iwEACmpzb25TdHJpbmcBAC4oTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyO0xqYXZhL2xhbmcvU3RyaW5nOylWCwCDAI0MAI4A"
    "ggEACGdldFZhbHVlCgBKAJAMAJEAkgEACWpzb25WYWx1ZQEALihMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7TGphdmEvbGFu"
    "Zy9PYmplY3Q7KVYHAJQBAA5qYXZhL3V0aWwvTGlzdAsAkwB1BwCXAQARamF2YS9sYW5nL0Jvb2xlYW4HAJkBABBqYXZhL2xh"
    "bmcvTnVtYmVyCgACAB0IAJwBABFBV1NfQUNDRVNTX0tFWV9JRAoAngCfBwCgDAChAKIBABBqYXZhL2xhbmcvU3lzdGVtAQAG"
    "Z2V0ZW52AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsIAKQBABVBV1NfU0VDUkVUX0FDQ0VTU19L"
    "RVkIAKYBABFBV1NfU0VTU0lPTl9UT0tFTggAqAEACkFXU19SRUdJT04SAAAAqgwAqwCiAQAXbWFrZUNvbmNhdFdpdGhDb25z"
    "dGFudHMIAK0BAAsiUXVldWVVcmwiOggArwEADywiTWVzc2FnZUJvZHkiOgoASgCxDACyAKIBAAlzaGEyNTZoZXgIALQBABR5"
    "eXl5TU1kZCdUJ0hIbW1zcydaJwoAtgC3BwC4DAC5ALoBACJqYXZhL3RpbWUvZm9ybWF0L0RhdGVUaW1lRm9ybWF0dGVyAQAJ"
    "b2ZQYXR0ZXJuAQA4KExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS90aW1lL2Zvcm1hdC9EYXRlVGltZUZvcm1hdHRlcjsJALwA"
    "vQcAvgwAvwDAAQAUamF2YS90aW1lL1pvbmVPZmZzZXQBAANVVEMBABZMamF2YS90aW1lL1pvbmVPZmZzZXQ7CgC2AMIMAMMA"
    "xAEACHdpdGhab25lAQA4KExqYXZhL3RpbWUvWm9uZUlkOylMamF2YS90aW1lL2Zvcm1hdC9EYXRlVGltZUZvcm1hdHRlcjsI"
    "AMYBAAh5eXl5TU1kZAoAyADJBwDKDADLAMwBABFqYXZhL3RpbWUvSW5zdGFudAEAA25vdwEAFSgpTGphdmEvdGltZS9JbnN0"
    "YW50OwoAtgDODAAWAM8BADkoTGphdmEvdGltZS90ZW1wb3JhbC9UZW1wb3JhbEFjY2Vzc29yOylMamF2YS9sYW5nL1N0cmlu"
    "ZzsSAAEA0QwAqwDSAQBKKExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylM"
    "amF2YS9sYW5nL1N0cmluZzsIANQBAD5jb250ZW50LXR5cGU7aG9zdDt4LWFtei1kYXRlO3gtYW16LXNlY3VyaXR5LXRva2Vu"
    "O3gtYW16LXRhcmdldBIAAgDREgADANcMAKsA2AEAOChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGph"
    "dmEvbGFuZy9TdHJpbmc7EgAEANESAAUAqgoASgDcDADdAN4BAARobWFjAQAYKFtCTGphdmEvbGFuZy9TdHJpbmc7KVtCCADg"
    "AQADc3FzCADiAQAMYXdzNF9yZXF1ZXN0EgAGAOQMAKsA5QEAXChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmlu"
    "ZztMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7BwDnAQAMamF2YS9uZXQv"
    "VVJMEgAHAKoKAOYA6gwABQDrAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWCgDmAO0MAO4A7wEADm9wZW5Db25uZWN0aW9uAQAa"
    "KClMamF2YS9uZXQvVVJMQ29ubmVjdGlvbjsHAPEBACBqYXZheC9uZXQvc3NsL0h0dHBzVVJMQ29ubmVjdGlvbggA8wEABFBP"
    "U1QKAPAA9QwA9gDrAQAQc2V0UmVxdWVzdE1ldGhvZAoA8AD4DAD5APoBAAtzZXREb091dHB1dAEABChaKVYIAPwBAAxDb250"
    "ZW50LVR5cGUIAP4BABphcHBsaWNhdGlvbi94LWFtei1qc29uLTEuMAoA8AEADAEBAQIBABJzZXRSZXF1ZXN0UHJvcGVydHkB"
    "ACcoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KVYIAQQBAApYLUFtei1EYXRlCAEGAQAUWC1BbXotU2Vj"
    "dXJpdHktVG9rZW4IAQgBAAxYLUFtei1UYXJnZXQIAQoBABVBbWF6b25TUVMuU2VuZE1lc3NhZ2UIAQwBAA1BdXRob3JpemF0"
    "aW9uCgDwAQ4MAQ8BEAEAG3NldEZpeGVkTGVuZ3RoU3RyZWFtaW5nTW9kZQEABChJKVYKAPABEgwBEwEUAQAPZ2V0T3V0cHV0"
    "U3RyZWFtAQAYKClMamF2YS9pby9PdXRwdXRTdHJlYW07CgEWARcHARgMARkBGgEAFGphdmEvaW8vT3V0cHV0U3RyZWFtAQAF"
    "d3JpdGUBAAUoW0IpVgoBFgEcDAEdAAYBAAVjbG9zZQcBHwEAE2phdmEvbGFuZy9UaHJvd2FibGUKAR4BIQwBIgEjAQANYWRk"
    "U3VwcHJlc3NlZAEAGChMamF2YS9sYW5nL1Rocm93YWJsZTspVgoA8AElDAEmAFUBAA9nZXRSZXNwb25zZUNvZGUKAPABKAwB"
    "KQEqAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwoA8AEsDAEtASoBAA5nZXRFcnJvclN0cmVh"
    "bQcBLwEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtCgEuAAMKATIBMwcBNAwBNQE2AQATamF2YS9pby9JbnB1dFN0"
    "cmVhbQEABHJlYWQBAAUoW0IpSQoBLgE4DAEZATkBAAcoW0JJSSlWBwE7AQAaamF2YS9sYW5nL1J1bnRpbWVFeGNlcHRpb24I"
    "AT0BAAVVVEYtOAoBLgE/DAAeAKISAAgBQQwAqwFCAQAnKElMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7"
    "CgE6AOoIAUUBABFPQlNFUlZFX1FVRVVFX1VSTAoASgFHDAFIAQIBAAtzZW5kTWVzc2FnZQcBSgEAE2phdmEvbGFuZy9FeGNl"
    "cHRpb24IAUwBACVmYWlsZWQgdG8gcmVwb3J0IG1hdGNoZWQgZXZlbnQgdG8gU1FTCgE6AU4MAAUBTwEAKihMamF2YS9sYW5n"
    "L1N0cmluZztMamF2YS9sYW5nL1Rocm93YWJsZTspVgoASgFRDAFSAVMBAA1oYW5kbGVSZXF1ZXN0AQBQKExqYXZhL3V0aWwv"
    "TWFwO0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZhL2xhbmcvVm9pZDsHAVUB"
    "ADRjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL1JlcXVlc3RIYW5kbGVyAQAEQ29kZQEAD0xpbmVOdW1i"
    "ZXJUYWJsZQEADVN0YWNrTWFwVGFibGUHAVoBAAJbQgEACkV4Y2VwdGlvbnMHAV0BAC1jb20vYW1hem9uYXdzL3NlcnZpY2Vz"
    "L2xhbWJkYS9ydW50aW1lL0NvbnRleHQBAAlTaWduYXR1cmUBAHYoTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7"
    "TGphdmEvbGFuZy9PYmplY3Q7PjtMY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0OylMamF2"
    "YS9sYW5nL1ZvaWQ7AQBVKExqYXZhL2xhbmcvT2JqZWN0O0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1l"
    "L0NvbnRleHQ7KUxqYXZhL2xhbmcvT2JqZWN0OwEAEE1ldGhvZFBhcmFtZXRlcnMBAI9MamF2YS9sYW5nL09iamVjdDtMY29t"
    "L2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9SZXF1ZXN0SGFuZGxlcjxMamF2YS91dGlsL01hcDxMamF2YS9s"
    "YW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+O0xqYXZhL2xhbmcvVm9pZDs+OwEAClNvdXJjZUZpbGUBABdFdmVudEJy"
    "aWRnZUhhbmRsZXIuamF2YQEAEEJvb3RzdHJhcE1ldGhvZHMIAWcBABNzcXMuAS5hbWF6b25hd3MuY29tCAFpAQB2Y29udGVu"
    "dC10eXBlOmFwcGxpY2F0aW9uL3gtYW16LWpzb24tMS4wCmhvc3Q6AQp4LWFtei1kYXRlOgEKeC1hbXotc2VjdXJpdHktdG9r"
    "ZW46AQp4LWFtei10YXJnZXQ6QW1hem9uU1FTLlNlbmRNZXNzYWdlCggBawEADVBPU1QKLwoKAQoBCgEIAW0BABQBLwEvc3Fz"
    "L2F3czRfcmVxdWVzdAgBbwEAFkFXUzQtSE1BQy1TSEEyNTYKAQoBCgEIAXEBAAVBV1M0AQgBcwEAPUFXUzQtSE1BQy1TSEEy"
    "NTYgQ3JlZGVudGlhbD0BLwEsIFNpZ25lZEhlYWRlcnM9ASwgU2lnbmF0dXJlPQEIAXUBAApodHRwczovLwEvCAF3AQAiU2Vu"
    "ZE1lc3NhZ2UgZmFpbGVkIHN0YXR1cz0BIGJvZHk9AQ8GAXkKAXoBewcBfAwAqwF9AQAkamF2YS9sYW5nL2ludm9rZS9TdHJp"
    "bmdDb25jYXRGYWN0b3J5AQCYKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xhbmcvU3Ry"
    "aW5nO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvT2JqZWN0OylM"
    "amF2YS9sYW5nL2ludm9rZS9DYWxsU2l0ZTsBAAxJbm5lckNsYXNzZXMBAAVFbnRyeQcBgQEAJWphdmEvbGFuZy9pbnZva2Uv"
    "TWV0aG9kSGFuZGxlcyRMb29rdXAHAYMBAB5qYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMBAAZMb29rdXAAIQBKAAIA"
    "AQFUAAAACQABAAUABgABAVYAAAAdAAEAAQAAAAUqtwABsQAAAAEBVwAAAAYAAQAAABUACgBNAE4AAQFWAAAAegAGAAYAAAA9"
    "uwAHWbcACUwqTSy+PgM2BBUEHaIAJSwVBDM2BSsSCgS9AAJZAxUFuAAMU7gAErYAGFeEBAGn/9srtgAcsAAAAAIBVwAAAA4A"
    "AwAAABgACAAZADgAGgFYAAAAFwAC/wAQAAUHAVkHAAcHAVkBAQAA+AAnAAoA3QDeAAIBVgAAAEAABQADAAAAIBIguAAiTSy7"
    "AChZKhIgtwAqtgAtLCuyADG2ADe2ADuwAAAAAQFXAAAADgADAAAAHgAGAB8AFAAgAVsAAAAEAAEBSQAKALIAogACAVYAAAAx"
    "AAMAAgAAABUSP7gAQUwrKrIAMbYAN7YARrgASbAAAAABAVcAAAAKAAIAAAAkAAYAJQFbAAAABAABAUkACgCKAIsAAQFWAAAB"
    "GAAGAAQAAACwKhAitgBPVwM9HCu2AFKiAJorHLYAVj4dqwAAAAAAAGYAAAAFAAAACQAAAFwAAAAKAAAASAAAAA0AAABSAAAA"
    "IgAAADQAAABcAAAAPioSWrYAGFenAE8qEly2ABhXpwBFKhJetgAYV6cAOyoSYLYAGFenADEqEmK2ABhXpwAnHRAgogAbKhJk"
    "BL0AAlkDHbgAZlO4ABK2ABhXpwAJKh22AE9XhAIBp/9kKhAitgBPV7EAAAACAVcAAAA6AA4AAAApAAcAKgARACsAFwAsAEwA"
    "LQBWAC4AYAAvAGoAMAB0ADEAfgAzAJwANACiACoAqAA3AK8AOAFYAAAAFgAK/AAJAfwAQgEJCQkJCR36AAX6AAUACgCRAJIA"
    "AQFWAAABsgACAAUAAAD7K8cADSoSa7YAGFenAO8rwQBtmQBpKhB7tgBPVwQ9K8AAbbkAbwEAuQBzAQBOLbkAeQEAmQA+LbkA"
    "fwEAwACDOgQcmgAKKhAstgBPVwM9KhkEuQCFAQDAABO4AIgqEDq2AE9XKhkEuQCMAQC4AI+n/78qEH22AE9XpwCCK8EAk5kA"
    "RyoQW7YAT1cEPSvAAJO5AJUBAE4tuQB5AQCZACEtuQB/AQA6BByaAAoqECy2AE9XAz0qGQS4AI+n/9wqEF22AE9XpwA3K8EA"
    "E5kADiorwAATuACIpwAlK8EAlpoACivBAJiZAA8qK7YAmrYAGFenAAsqK7YAmrgAiLEAAAACAVcAAAByABwAAAA8AAQAPQAO"
    "AD4AFQA/ABwAQAAeAEEAQQBCAEwAQwBOAEQAXABFAGMARgBuAEcAcQBIAHgASQCCAEoAiQBLAIsATACmAE0AsQBOALMATwC5"
    "AFAAvABRAMMAUgDNAFMA2ABUAOYAVQDyAFcA+gBZAVgAAAAtAA0O/QAeAQcAevwAHgcAg/kAJPoACf0AGQEHAHr8ABsHAAL5"
    "AAr6AAkRDQsHAAoBSAECAAIBVgAABDMABQAjAAACOxKbuACdTRKjuACdThKluACdOgQSp7gAnToFGQW6AKkAADoGuwAHWbcA"
    "CToHGQcQe7YAT1cZBxKstgAYVxkHKrgAiBkHEq62ABhXGQcruACIGQcQfbYAT1cZB7YAHDoIGQi4ALA6CRKzuAC1sgC7tgDB"
    "OgoSxbgAtbIAu7YAwToLuADHOgwZChkMtgDNOg0ZCxkMtgDNOg4ZBhkNGQS6ANAAADoPEtM6EBkPGRAZCboA1QAAOhEZDhkF"
    "ugDWAAA6EhkNGRIZEbgAsLoA2QAAOhMtugDaAACyADG2ADc6FBkUGQ64ANs6FRkVGQW4ANs6FhkWEt+4ANs6FxkXEuG4ANs6"
    "GBkYGRO4ANu4AEk6GSwZEhkQGRm6AOMAADoauwDmWRkGugDoAAC3AOk6GxkbtgDswADwOhwZHBLytgD0GRwEtgD3GRwS+xL9"
    "tgD/GRwTAQMZDbYA/xkcEwEFGQS2AP8ZHBMBBxMBCbYA/xkcEwELGRq2AP8ZCLIAMbYANzodGRwZHb62AQ0ZHLYBEToeGR4Z"
    "HbYBFRkexgAmGR62ARunAB46HxkexgAUGR62ARunAAw6IBkfGSC2ASAZH78ZHLYBJDYeFR4RAMihABMVHhEBLKIACxkctgEn"
    "pwAIGRy2ASs6H7sBLlm3ATA6IBEQALwIOiEZH8YAHhkfGSG2ATFZNiICnwAQGSAZIQMVIrYBN6f/4xUeEQDIoQALFR4RASyh"
    "ABq7ATpZFR4ZIBMBPLYBProBQAAAtwFDv7EAAgGOAZUBogEeAakBrgGxAR4AAgFXAAAA4gA4AAAAXQAGAF4ADABfABMAYAAa"
    "AGEAIwBjACwAZAA0AGUAPABmAEIAZwBKAGgAUABpAFgAagBfAGsAZgBtAHMAbgCAAG8AhQBwAI4AcQCXAHMApAB5AKgAewC1"
    "AHwAwAB9AMYAfgDQAIAA3gCBAOcAggDwAIMA+QCEAQIAhQEOAIcBHACKASwAiwE2AIwBPQCNAUMAjgFMAI8BVgCQAWAAkQFr"
    "AJIBdQCTAX8AlAGHAJUBjgCWAZUAlwGiAJUBvQCYAcQAmQHjAJoB7ACbAfMAnQITAJ4CIwCfAi4AoAI6AKIBWAAAAO4ACv8B"
    "ogAfBwATBwATBwATBwATBwATBwATBwATBwAHBwATBwATBwC2BwC2BwDIBwATBwATBwATBwATBwATBwATBwATBwFZBwFZBwFZ"
    "BwFZBwFZBwATBwATBwDmBwDwBwFZBwEWAAEHAR7/AA4AIAcAEwcAEwcAEwcAEwcAEwcAEwcAEwcABwcAEwcAEwcAtgcAtgcA"
    "yAcAEwcAEwcAEwcAEwcAEwcAEwcAEwcBWQcBWQcBWQcBWQcBWQcAEwcAEwcA5gcA8AcBWQcBFgcBHgABBwEeCPkAAvwAHgFE"
    "BwEy/gARBwEyBwEuBwFZHw8WAVsAAAAEAAEBSQABAVIBUwACAVYAAACRAAQABgAAADMTAUS4AJ1OuwAHWbcACToEGQQruACP"
    "LRkEtgAcuAFGpwASOgW7ATpZEwFLGQW3AU2/AbAAAQAWAB8AIgFJAAIBVwAAACIACAAAAKYABwCnABAAqAAWAKoAHwCtACIA"
    "qwAkAKwAMQCuAVgAAAAcAAL/ACIABQcASgcAbQcBXAcAEwcABwABBwFJDgFeAAAAAgFfEEEBUgFgAAIBVgAAACIAAwADAAAA"
    "CiorwABtLLYBULAAAAABAVcAAAAGAAEAAAAVAWEAAAAJAgAAEAAAABAAAAQBXgAAAAIBYgFjAAAAAgFkAWUAAAA4AAkBeAAB"
    "AWYBeAABAWgBeAABAWoBeAABAWwBeAABAW4BeAABAXABeAABAXIBeAABAXQBeAABAXYBfgAAABIAAgCDAG0BfwYJAYABggGE"
    "ABk="
)


def _deployment_zip() -> bytes:
    raw = base64.b64decode(_B64)
    got = hashlib.sha256(raw).hexdigest()
    assert got == _SHA256, f"embedded class is sha256 {got!r}, pinned {_SHA256!r}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("probe/EventBridgeHandler.class", raw)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


def _queue(ctx):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-javaevb-q-")
    sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})
    url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    return {"name": name, "url": url, "arn": arn}


def _execution_role(ctx, *, queue_arn):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-javaevb-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    inline = "sim2real-inline"
    iam.put_role_policy(RoleName=name, PolicyName=inline, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName=inline),
                             "NoSuchEntity"))
    return arn


def _create(ctx, lam, kwargs, timeout_s=120):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "cannot be assumed by Lambda" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                if propagating and _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateFunction: the run budget ended first while the execution role "
                        "was still propagating; not graded"
                    ) from exc
                raise
            time.sleep(2.0)


def _wait_active(ctx, lam, fn, timeout_s=300):
    return _poll_until(
        ctx, lambda: lam.get_function_configuration(FunctionName=fn),
        lambda cfg: cfg["State"] == "Active", timeout_s=timeout_s, interval_s=2.0,
        description=f"{fn} reaching State=Active")


def _function(ctx, lam, **kwargs):
    fn = kwargs["FunctionName"]
    _create(ctx, lam, kwargs)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    _wait_active(ctx, lam, fn)
    return fn


def _drain(sqs, url) -> list:
    out = []
    while True:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        msgs = resp.get("Messages", [])
        if not msgs:
            return out
        for m in msgs:
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Java RequestHandler<Map,Void> reads an EventBridge rule target's event through the
    generic Map the runtime hands it: source, detail-type and the detail object's own field
    reach the handler exactly as PutEvents sent them.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-lambda-target.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    """
    events = ctx.client("events")
    lam = ctx.client("lambda")

    observe = _queue(ctx)
    role_arn = _execution_role(ctx, queue_arn=observe["arn"])
    fn = ctx.unique_name("sim2real-behav-javaevb-fn-")
    fn = _function(ctx, lam, FunctionName=fn, Runtime="java25",
                   Handler="probe.EventBridgeHandler", Role=role_arn,
                   Code={"ZipFile": _deployment_zip()}, MemorySize=512, Timeout=20,
                   Environment={"Variables": {"OBSERVE_QUEUE_URL": observe["url"]}},
                   Tags={"sim2real": CHECK})
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]

    source = ctx.unique_name("sim2real.behav.javaevb.")
    rule_name = ctx.unique_name("sim2real-behav-javaevb-rule-")
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps({"source": [source]}), State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}])["RuleArn"]
    ctx.on_cleanup(_teardown(lambda: events.delete_rule(Name=rule_name), "ResourceNotFoundException"))

    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": fn_arn}])
    ctx.on_cleanup(_teardown(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]),
                             "ResourceNotFoundException"))

    lam.add_permission(FunctionName=fn, StatementId="events-invoke",
                       Action="lambda:InvokeFunction", Principal="events.amazonaws.com",
                       SourceArn=rule_arn)

    account = ctx.account
    sqs = ctx.client("sqs")

    # A rule's target wiring can take a short window to propagate across EventBridge's control
    # plane; an event sent inside that window is dropped rather than queued, so a fresh probe (its
    # own unique foo) is sent every round rather than waiting on a single PutEvents call.
    rec = None
    deadline = time.monotonic() + _budget_s(ctx, 300.0)
    while time.monotonic() < deadline and rec is None:
        foo_value = ctx.unique_name("probe-foo-")
        events.put_events(Entries=[{
            "Source": source, "DetailType": "probe-detail-type",
            "Detail": json.dumps({"foo": foo_value})}])
        round_end = time.monotonic() + 20.0
        while time.monotonic() < round_end:
            time.sleep(2.0)
            for r in _drain(sqs, observe["url"]):
                if r.get("detail", {}).get("foo") == foo_value:
                    rec = r
                    break
            if rec is not None:
                break
    if rec is None and _budget_spent(ctx):
        raise TimeoutError(
            "no PutEvents entry reached the Java handler: the run budget ended first; not graded")
    assert rec is not None, (
        "no PutEvents entry reached the Java handler within 300s — the rule never delivered")
    assert rec["source"] == source, f"source reaching the handler was {rec['source']!r}"
    assert rec["detail-type"] == "probe-detail-type", (
        f"detail-type reaching the handler was {rec['detail-type']!r}")
    assert rec.get("account") == account, (
        f"account reaching the handler was {rec.get('account')!r}, expected {account!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

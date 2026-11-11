"""java-s3-notification-record-fields-reach-the-handler."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-s3-notification-record-fields-reach-the-handler"
GROUP = "eventing"
SERVICES = ["lambda", "s3", "sqs"]

# com.amazonaws.services.lambda.runtime.RequestHandler<Map<String,Object>, Void>: the S3 event
# notification's Records list reaches the handler as a generic Map (no S3Event POJO), and the
# handler URL-decodes each record's object key and relays eventName, bucket name, key and size
# as JSON to an SQS queue the check owns, signing the SendMessage call itself (no AWS SDK
# bundled) so the check can verify them against the object it actually uploaded.
_SHA256 = "2051ff4c475eb0c6d57b1c13e6eb08915b4d95862f1091ea10176116586c9611"

_B64 = (  # @@GENERATED@@ probe/S3EventHandler.class
    "yv66vgAAAD0BlgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWBwAIAQAXamF2YS9sYW5n"
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
    "aWdlc3Q7CgBCAEcMAEgAPgEABmRpZ2VzdAoASgBLBwBMDABNAE4BABRwcm9iZS9TM0V2ZW50SGFuZGxlcgEAA2hleAEAFihb"
    "QilMamF2YS9sYW5nL1N0cmluZzsKAAcAUAwAGgBRAQAcKEMpTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwoAEwBTDABUAFUB"
    "AAZsZW5ndGgBAAMoKUkKABMAVwwAWABZAQAGY2hhckF0AQAEKEkpQwgAWwEAAlwiCABdAQACXFwIAF8BAAJcbggAYQEAAlxy"
    "CABjAQACXHQIAGUBAAZcdSUwNHgKAGcAaAcAaQwAEABqAQARamF2YS9sYW5nL0ludGVnZXIBABYoSSlMamF2YS9sYW5nL0lu"
    "dGVnZXI7CgACAB0IAG0BABFBV1NfQUNDRVNTX0tFWV9JRAoAbwBwBwBxDAByAHMBABBqYXZhL2xhbmcvU3lzdGVtAQAGZ2V0"
    "ZW52AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsIAHUBABVBV1NfU0VDUkVUX0FDQ0VTU19LRVkI"
    "AHcBABFBV1NfU0VTU0lPTl9UT0tFTggAeQEACkFXU19SRUdJT04SAAAAewwAfABzAQAXbWFrZUNvbmNhdFdpdGhDb25zdGFu"
    "dHMIAH4BAAsiUXVldWVVcmwiOgoASgCADACBAIIBAApqc29uU3RyaW5nAQAuKExqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjtM"
    "amF2YS9sYW5nL1N0cmluZzspVggAhAEADywiTWVzc2FnZUJvZHkiOgoASgCGDACHAHMBAAlzaGEyNTZoZXgIAIkBABR5eXl5"
    "TU1kZCdUJ0hIbW1zcydaJwoAiwCMBwCNDACOAI8BACJqYXZhL3RpbWUvZm9ybWF0L0RhdGVUaW1lRm9ybWF0dGVyAQAJb2ZQ"
    "YXR0ZXJuAQA4KExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS90aW1lL2Zvcm1hdC9EYXRlVGltZUZvcm1hdHRlcjsJAJEAkgcA"
    "kwwAlACVAQAUamF2YS90aW1lL1pvbmVPZmZzZXQBAANVVEMBABZMamF2YS90aW1lL1pvbmVPZmZzZXQ7CgCLAJcMAJgAmQEA"
    "CHdpdGhab25lAQA4KExqYXZhL3RpbWUvWm9uZUlkOylMamF2YS90aW1lL2Zvcm1hdC9EYXRlVGltZUZvcm1hdHRlcjsIAJsB"
    "AAh5eXl5TU1kZAoAnQCeBwCfDACgAKEBABFqYXZhL3RpbWUvSW5zdGFudAEAA25vdwEAFSgpTGphdmEvdGltZS9JbnN0YW50"
    "OwoAiwCjDAAWAKQBADkoTGphdmEvdGltZS90ZW1wb3JhbC9UZW1wb3JhbEFjY2Vzc29yOylMamF2YS9sYW5nL1N0cmluZzsS"
    "AAEApgwAfACnAQBKKExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2"
    "YS9sYW5nL1N0cmluZzsIAKkBAD5jb250ZW50LXR5cGU7aG9zdDt4LWFtei1kYXRlO3gtYW16LXNlY3VyaXR5LXRva2VuO3gt"
    "YW16LXRhcmdldBIAAgCmEgADAKwMAHwArQEAOChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGphdmEv"
    "bGFuZy9TdHJpbmc7EgAEAKYSAAUAewoASgCxDACyALMBAARobWFjAQAYKFtCTGphdmEvbGFuZy9TdHJpbmc7KVtCCAC1AQAD"
    "c3FzCAC3AQAMYXdzNF9yZXF1ZXN0EgAGALkMAHwAugEAXChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztM"
    "amF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7BwC8AQAMamF2YS9uZXQvVVJM"
    "EgAHAHsKALsAvwwABQDAAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWCgC7AMIMAMMAxAEADm9wZW5Db25uZWN0aW9uAQAaKClM"
    "amF2YS9uZXQvVVJMQ29ubmVjdGlvbjsHAMYBACBqYXZheC9uZXQvc3NsL0h0dHBzVVJMQ29ubmVjdGlvbggAyAEABFBPU1QK"
    "AMUAygwAywDAAQAQc2V0UmVxdWVzdE1ldGhvZAoAxQDNDADOAM8BAAtzZXREb091dHB1dAEABChaKVYIANEBAAxDb250ZW50"
    "LVR5cGUIANMBABphcHBsaWNhdGlvbi94LWFtei1qc29uLTEuMAoAxQDVDADWANcBABJzZXRSZXF1ZXN0UHJvcGVydHkBACco"
    "TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KVYIANkBAApYLUFtei1EYXRlCADbAQAUWC1BbXotU2VjdXJp"
    "dHktVG9rZW4IAN0BAAxYLUFtei1UYXJnZXQIAN8BABVBbWF6b25TUVMuU2VuZE1lc3NhZ2UIAOEBAA1BdXRob3JpemF0aW9u"
    "CgDFAOMMAOQA5QEAG3NldEZpeGVkTGVuZ3RoU3RyZWFtaW5nTW9kZQEABChJKVYKAMUA5wwA6ADpAQAPZ2V0T3V0cHV0U3Ry"
    "ZWFtAQAYKClMamF2YS9pby9PdXRwdXRTdHJlYW07CgDrAOwHAO0MAO4A7wEAFGphdmEvaW8vT3V0cHV0U3RyZWFtAQAFd3Jp"
    "dGUBAAUoW0IpVgoA6wDxDADyAAYBAAVjbG9zZQcA9AEAE2phdmEvbGFuZy9UaHJvd2FibGUKAPMA9gwA9wD4AQANYWRkU3Vw"
    "cHJlc3NlZAEAGChMamF2YS9sYW5nL1Rocm93YWJsZTspVgoAxQD6DAD7AFUBAA9nZXRSZXNwb25zZUNvZGUKAMUA/QwA/gD/"
    "AQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwoAxQEBDAECAP8BAA5nZXRFcnJvclN0cmVhbQcB"
    "BAEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtCgEDAAMKAQcBCAcBCQwBCgELAQATamF2YS9pby9JbnB1dFN0cmVh"
    "bQEABHJlYWQBAAUoW0IpSQoBAwENDADuAQ4BAAcoW0JJSSlWBwEQAQAaamF2YS9sYW5nL1J1bnRpbWVFeGNlcHRpb24IARIB"
    "AAVVVEYtOAoBAwEUDAAeAHMSAAgBFgwAfAEXAQAnKElMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7CgEP"
    "AL8IARoBABFPQlNFUlZFX1FVRVVFX1VSTAgBHAEAB1JlY29yZHMLAR4BHwcBIAwBIQEiAQANamF2YS91dGlsL01hcAEAA2dl"
    "dAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7BwEkAQAOamF2YS91dGlsL0xpc3QLASMBJgwBJwEo"
    "AQAIaXRlcmF0b3IBABYoKUxqYXZhL3V0aWwvSXRlcmF0b3I7CwEqASsHASwMAS0BLgEAEmphdmEvdXRpbC9JdGVyYXRvcgEA"
    "B2hhc05leHQBAAMoKVoLASoBMAwBMQEyAQAEbmV4dAEAFCgpTGphdmEvbGFuZy9PYmplY3Q7CAE0AQACczMIATYBAAZidWNr"
    "ZXQIATgBAAZvYmplY3QIAToBAANrZXkKATwBPQcBPgwBPwCtAQATamF2YS9uZXQvVVJMRGVjb2RlcgEABmRlY29kZQcBQQEA"
    "E2phdmEvbGFuZy9FeGNlcHRpb24IAUMBAB9mYWlsZWQgdG8gVVJMLWRlY29kZSBvYmplY3Qga2V5CgEPAUUMAAUBRgEAKihM"
    "amF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1Rocm93YWJsZTspVggBSAEADCJldmVudE5hbWUiOggBSgEACWV2ZW50TmFt"
    "ZQgBTAEADywiZXZlbnRTb3VyY2UiOggBTgEAC2V2ZW50U291cmNlCAFQAQAKLCJidWNrZXQiOggBUgEABG5hbWUIAVQBAAcs"
    "ImtleSI6CAFWAQAILCJzaXplIjoIAVgBAARzaXplCgBKAVoMAVsBXAEACmpzb25OdW1iZXIBAC4oTGphdmEvbGFuZy9TdHJp"
    "bmdCdWlsZGVyO0xqYXZhL2xhbmcvT2JqZWN0OylWCgBKAV4MAV8A1wEAC3NlbmRNZXNzYWdlCAFhAQAuZmFpbGVkIHRvIHJl"
    "cG9ydCBTMyBub3RpZmljYXRpb24gcmVjb3JkIHRvIFNRUwoASgFjDAFkAWUBAA1oYW5kbGVSZXF1ZXN0AQBQKExqYXZhL3V0"
    "aWwvTWFwO0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZhL2xhbmcvVm9pZDsH"
    "AWcBADRjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL1JlcXVlc3RIYW5kbGVyAQAEQ29kZQEAD0xpbmVO"
    "dW1iZXJUYWJsZQEADVN0YWNrTWFwVGFibGUHAWwBAAJbQgEACkV4Y2VwdGlvbnMHAW8BAC1jb20vYW1hem9uYXdzL3NlcnZp"
    "Y2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQBAAlTaWduYXR1cmUBAHYoTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJp"
    "bmc7TGphdmEvbGFuZy9PYmplY3Q7PjtMY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0OylM"
    "amF2YS9sYW5nL1ZvaWQ7AQBVKExqYXZhL2xhbmcvT2JqZWN0O0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50"
    "aW1lL0NvbnRleHQ7KUxqYXZhL2xhbmcvT2JqZWN0OwEAEE1ldGhvZFBhcmFtZXRlcnMBAI9MamF2YS9sYW5nL09iamVjdDtM"
    "Y29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9SZXF1ZXN0SGFuZGxlcjxMamF2YS91dGlsL01hcDxMamF2"
    "YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+O0xqYXZhL2xhbmcvVm9pZDs+OwEAClNvdXJjZUZpbGUBABNTM0V2"
    "ZW50SGFuZGxlci5qYXZhAQAQQm9vdHN0cmFwTWV0aG9kcwgBeQEAE3Nxcy4BLmFtYXpvbmF3cy5jb20IAXsBAHZjb250ZW50"
    "LXR5cGU6YXBwbGljYXRpb24veC1hbXotanNvbi0xLjAKaG9zdDoBCngtYW16LWRhdGU6AQp4LWFtei1zZWN1cml0eS10b2tl"
    "bjoBCngtYW16LXRhcmdldDpBbWF6b25TUVMuU2VuZE1lc3NhZ2UKCAF9AQANUE9TVAovCgoBCgEKAQgBfwEAFAEvAS9zcXMv"
    "YXdzNF9yZXF1ZXN0CAGBAQAWQVdTNC1ITUFDLVNIQTI1NgoBCgEKAQgBgwEABUFXUzQBCAGFAQA9QVdTNC1ITUFDLVNIQTI1"
    "NiBDcmVkZW50aWFsPQEvASwgU2lnbmVkSGVhZGVycz0BLCBTaWduYXR1cmU9AQgBhwEACmh0dHBzOi8vAS8IAYkBACJTZW5k"
    "TWVzc2FnZSBmYWlsZWQgc3RhdHVzPQEgYm9keT0BDwYBiwoBjAGNBwGODAB8AY8BACRqYXZhL2xhbmcvaW52b2tlL1N0cmlu"
    "Z0NvbmNhdEZhY3RvcnkBAJgoTGphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcyRMb29rdXA7TGphdmEvbGFuZy9TdHJp"
    "bmc7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9PYmplY3Q7KUxq"
    "YXZhL2xhbmcvaW52b2tlL0NhbGxTaXRlOwEADElubmVyQ2xhc3NlcwcBkgEAJWphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFu"
    "ZGxlcyRMb29rdXAHAZQBAB5qYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMBAAZMb29rdXAAIQBKAAIAAQFmAAAACQAB"
    "AAUABgABAWgAAAAdAAEAAQAAAAUqtwABsQAAAAEBaQAAAAYAAQAAABYACgBNAE4AAQFoAAAAegAGAAYAAAA9uwAHWbcACUwq"
    "TSy+PgM2BBUEHaIAJSwVBDM2BSsSCgS9AAJZAxUFuAAMU7gAErYAGFeEBAGn/9srtgAcsAAAAAIBaQAAAA4AAwAAABkACAAa"
    "ADgAGwFqAAAAFwAC/wAQAAUHAWsHAAcHAWsBAQAA+AAnAAoAsgCzAAIBaAAAAEAABQADAAAAIBIguAAiTSy7AChZKhIgtwAq"
    "tgAtLCuyADG2ADe2ADuwAAAAAQFpAAAADgADAAAAHwAGACAAFAAhAW0AAAAEAAEBQAAKAIcAcwACAWgAAAAxAAMAAgAAABUS"
    "P7gAQUwrKrIAMbYAN7YARrgASbAAAAABAWkAAAAKAAIAAAAlAAYAJgFtAAAABAABAUAACgCBAIIAAQFoAAABGAAGAAQAAACw"
    "KhAitgBPVwM9HCu2AFKiAJorHLYAVj4dqwAAAAAAAGYAAAAFAAAACQAAAFwAAAAKAAAASAAAAA0AAABSAAAAIgAAADQAAABc"
    "AAAAPioSWrYAGFenAE8qEly2ABhXpwBFKhJetgAYV6cAOyoSYLYAGFenADEqEmK2ABhXpwAnHRAgogAbKhJkBL0AAlkDHbgA"
    "ZlO4ABK2ABhXpwAJKh22AE9XhAIBp/9kKhAitgBPV7EAAAACAWkAAAA6AA4AAAAqAAcAKwARACwAFwAtAEwALgBWAC8AYAAw"
    "AGoAMQB0ADIAfgA0AJwANQCiACsAqAA4AK8AOQFqAAAAFgAK/AAJAfwAQgEJCQkJCR36AAX6AAUACgFbAVwAAQFoAAAAJgAC"
    "AAIAAAAKKiu2AGu2ABhXsQAAAAEBaQAAAAoAAgAAADwACQA9AAoBXwDXAAIBaAAABC4ABQAjAAACNhJsuABuTRJ0uABuThJ2"
    "uABuOgQSeLgAbjoFGQW6AHoAADoGuwAHWbcACToHGQcQe7YAT1cZBxJ9tgAYVxkHKrgAfxkHEoO2ABhXGQcruAB/GQcQfbYA"
    "T1cZB7YAHDoIGQi4AIU6CRKIuACKsgCQtgCWOgoSmrgAirIAkLYAljoLuACcOgwZChkMtgCiOg0ZCxkMtgCiOg4ZBhkNGQS6"
    "AKUAADoPEqg6EBkPGRAZCboAqgAAOhEZDhkFugCrAAA6EhkNGRIZEbgAhboArgAAOhMtugCvAACyADG2ADc6FBkUGQ64ALA6"
    "FRkVGQW4ALA6FhkWErS4ALA6FxkXEra4ALA6GBkYGRO4ALC4AEk6GSwZEhkQGRm6ALgAADoauwC7WRkGugC9AAC3AL46Gxkb"
    "tgDBwADFOhwZHBLHtgDJGRwEtgDMGRwS0BLStgDUGRwS2BkNtgDUGRwS2hkEtgDUGRwS3BLetgDUGRwS4BkatgDUGQiyADG2"
    "ADc6HRkcGR2+tgDiGRy2AOY6HhkeGR22AOoZHsYAJhketgDwpwAeOh8ZHsYAFBketgDwpwAMOiAZHxkgtgD1GR+/GRy2APk2"
    "HhUeEQDIoQATFR4RASyiAAsZHLYA/KcACBkctgEAOh+7AQNZtwEFOiAREAC8CDohGR/GAB4ZHxkhtgEGWTYiAp8AEBkgGSED"
    "FSK2AQyn/+MVHhEAyKEACxUeEQEsoQAauwEPWRUeGSATARG2ARO6ARUAALcBGL+xAAIBiQGQAZ0A8wGkAakBrADzAAIBaQAA"
    "AOIAOAAAAEEABgBCAAwAQwATAEQAGgBFACMARwAsAEgANABJADwASgBCAEsASgBMAFAATQBYAE4AXwBPAGYAUQBzAFIAgABT"
    "AIUAVACOAFUAlwBXAKQAXQCoAF8AtQBgAMAAYQDGAGIA0ABkAN4AZQDnAGYA8ABnAPkAaAECAGkBDgBrARwAbgEsAG8BNgBw"
    "AT0AcQFDAHIBTABzAVUAdAFeAHUBZwB2AXAAdwF6AHgBggB5AYkAegGQAHsBnQB5AbgAfAG/AH0B3gB+AecAfwHuAIECDgCC"
    "Ah4AgwIpAIQCNQCGAWoAAADuAAr/AZ0AHwcAEwcAEwcAEwcAEwcAEwcAEwcAEwcABwcAEwcAEwcAiwcAiwcAnQcAEwcAEwcA"
    "EwcAEwcAEwcAEwcAEwcBawcBawcBawcBawcBawcAEwcAEwcAuwcAxQcBawcA6wABBwDz/wAOACAHABMHABMHABMHABMHABMH"
    "ABMHABMHAAcHABMHABMHAIsHAIsHAJ0HABMHABMHABMHABMHABMHABMHABMHAWsHAWsHAWsHAWsHAWsHABMHABMHALsHAMUH"
    "AWsHAOsHAPMAAQcA8wj5AAL8AB4BRAcBB/4AEQcBBwcBAwcBax8PFgFtAAAABAABAUAAAQFkAWUAAgFoAAACbAAEAA4AAAE+"
    "EwEZuABuTisTARu5AR0CAMABIzoEGQS5ASUBADoFGQW5ASkBAJkBFxkFuQEvAQA6BhkGwAEeOgcZBxMBM7kBHQIAwAEeOggZ"
    "CBMBNbkBHQIAwAEeOgkZCBMBN7kBHQIAwAEeOgoZChMBObkBHQIAwAATEwERuAE7OgunABI6DLsBD1kTAUIZDLcBRL+7AAdZ"
    "twAJOgwZDBB7tgBPVxkMEwFHtgAYVxkMGQcTAUm5AR0CAMAAE7gAfxkMEwFLtgAYVxkMGQcTAU25AR0CAMAAE7gAfxkMEwFP"
    "tgAYVxkMGQkTAVG5AR0CAMAAE7gAfxkMEwFTtgAYVxkMGQu4AH8ZDBMBVbYAGFcZDBkKEwFXuQEdAgC4AVkZDBB9tgBPVy0Z"
    "DLYAHLgBXacAEjoNuwEPWRMBYBkNtwFEv6f+5QGwAAIAZQB6AH0BQAEeAScBKgFAAAIBaQAAAHoAHgAAAIsABwCMABUAjQAx"
    "AI4AOACPAEcAkABWAJEAZQCUAHoAlwB9AJUAfwCWAIwAmACVAJkAnQCaAKYAmwC4AJwAwQCdANMAngDcAJ8A7gCgAPcAoQD+"
    "AKIBBwCjARYApAEeAKYBJwCpASoApwEsAKgBOQCqATwAqwFqAAAAjAAG/gAeBwATBwEjBwEq/wBeAAsHAEoHAR4HAW4HABMH"
    "ASMHASoHAAIHAR4HAR4HAR4HAR4AAQcBQPwADgcAE/8AnQANBwBKBwEeBwFuBwATBwEjBwEqBwACBwEeBwEeBwEeBwEeBwAT"
    "BwAHAAEHAUD/AA4ABgcASgcBHgcBbgcAEwcBIwcBKgAA+gACAXAAAAACAXEQQQFkAXIAAgFoAAAAIgADAAMAAAAKKivAAR4s"
    "tgFisAAAAAEBaQAAAAYAAQAAABYBcwAAAAkCAAAQAAAAEAAABAFwAAAAAgF0AXUAAAACAXYBdwAAADgACQGKAAEBeAGKAAEB"
    "egGKAAEBfAGKAAEBfgGKAAEBgAGKAAEBggGKAAEBhAGKAAEBhgGKAAEBiAGQAAAACgABAZEBkwGVABk="
)


#: AWS documents S3 notification config changes taking "usually about five minutes" to arm, with
#: no upper bound and events before arming DROPPED and never redelivered — so a fresh key is
#: uploaded every round rather than waiting on one.
_PROPAGATION_DEADLINE_S = 600.0
_PROPAGATION_ROUND_S = 15.0


def _deployment_zip() -> bytes:
    raw = base64.b64decode(_B64)
    got = hashlib.sha256(raw).hexdigest()
    assert got == _SHA256, f"embedded class is sha256 {got!r}, pinned {_SHA256!r}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("probe/S3EventHandler.class", raw)
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
    name = ctx.unique_name("sim2real-behav-javas3-q-")
    sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})
    url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    return {"name": name, "url": url, "arn": arn}


def _execution_role(ctx, *, queue_arn):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-javas3-role-")
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
            if propagating and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            if propagating and _budget_spent(ctx):
                raise TimeoutError(f"CreateFunction {kwargs['FunctionName']}: the run budget ended first; not graded") from exc
            raise


def _wait_active(ctx, lam, fn, timeout_s=300):
    return _poll_until(
        ctx, lambda: lam.get_function_configuration(FunctionName=fn),
        lambda cfg: cfg["State"] == "Active", timeout_s=timeout_s,
        description=f"{fn} reaching State=Active")


def _function(ctx, lam, **kwargs):
    fn = kwargs["FunctionName"]
    _create(ctx, lam, kwargs)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    _wait_active(ctx, lam, fn)
    return fn


def _create_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-behav-javas3-bkt-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, bucket):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


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
    """A Java RequestHandler<Map,Void> reads an S3 event notification's Records list through the
    generic Map the runtime hands it: eventName, the bucket name and the object key and size
    reach the handler unchanged from a PutObject.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-s3.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    """
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")

    bucket = _create_bucket(ctx, s3)
    observe = _queue(ctx)
    role_arn = _execution_role(ctx, queue_arn=observe["arn"])
    fn = ctx.unique_name("sim2real-behav-javas3-fn-")
    fn = _function(ctx, lam, FunctionName=fn, Runtime="java17",
                   Handler="probe.S3EventHandler", Role=role_arn,
                   Code={"ZipFile": _deployment_zip()}, MemorySize=512, Timeout=20,
                   Environment={"Variables": {"OBSERVE_QUEUE_URL": observe["url"]}},
                   Tags={"sim2real": CHECK})

    lam.add_permission(FunctionName=fn, StatementId="s3invoke", Action="lambda:InvokeFunction",
                       Principal="s3.amazonaws.com", SourceArn=f"arn:aws:s3:::{bucket}")
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"LambdaFunctionConfigurations": [{
            "LambdaFunctionArn": fn_arn, "Events": ["s3:ObjectCreated:*"]}]})

    sqs = ctx.client("sqs")
    token = ctx.unique_name("probe").rsplit("-", 1)[-1]
    body = b"probe-body-for-fidelity-check"

    propagation_timeout_s = _budget_s(ctx, _PROPAGATION_DEADLINE_S)
    deadline = time.monotonic() + propagation_timeout_s
    rounds = 0
    record = None
    while time.monotonic() < deadline and record is None:
        rounds += 1
        last_key = f"raw/{token}-{rounds}.bin"
        s3.put_object(Bucket=bucket, Key=last_key, Body=body)
        round_end = time.monotonic() + _PROPAGATION_ROUND_S
        while time.monotonic() < round_end:
            time.sleep(5.0)
            for r in _drain(sqs, observe["url"]):
                if r.get("key") == last_key:
                    record = r
                    break
            if record is not None:
                break
    if record is None and _budget_spent(ctx):
        raise TimeoutError(
            f"waiting for a PutObject to reach the Java handler: the run budget ended first; "
            f"not graded"
        )
    assert record is not None, (
        f"no PutObject reached the Java handler within {propagation_timeout_s:.0f}s over "
        f"{rounds} round(s) — the notification never armed")

    assert record["eventName"] == "ObjectCreated:Put", (
        f"eventName was {record['eventName']!r}, expected exactly ObjectCreated:Put")
    assert record["bucket"] == bucket, (
        f"bucket name reaching the handler was {record['bucket']!r}, expected {bucket!r}")
    assert record["size"] == len(body), (
        f"size reaching the handler was {record['size']!r}, expected {len(body)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

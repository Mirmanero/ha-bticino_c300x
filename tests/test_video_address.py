"""Run with python -m unittest discover -s tests -v (no HA installation needed)."""

import ast
import importlib
import pathlib
import sys
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
# Load the protocol without running the integration's Home Assistant/cloud
# entrypoints. All dependencies of this module are standard-library modules.
PACKAGE = "_bticino_video_tests"
for name, directory in (
    (PACKAGE, ROOT),
    (f"{PACKAGE}.bticino_lib", ROOT / "bticino_lib"),
    (f"{PACKAGE}.bticino_lib.protocol", ROOT / "bticino_lib/protocol"),
):
    module = types.ModuleType(name)
    module.__path__ = [str(directory)]
    sys.modules[name] = module
sip = importlib.import_module(f"{PACKAGE}.bticino_lib.protocol.sip_client")


class VideoAddressTests(unittest.IsolatedAsyncioTestCase):
    def make_client(self, sockname=("192.0.2.10", 45000)):
        client = sip.BticinoSipClient(
            sip.SipCredentials("test", "test", "example.invalid"),
            local_ip="192.0.2.20", use_tls=False,
        )
        writer = Mock()
        writer.get_extra_info.return_value = sockname
        writer.drain = AsyncMock()
        return client, writer

    async def test_connect_still_targets_gateway(self):
        client, writer = self.make_client()
        with patch.object(sip.asyncio, "open_connection", new_callable=AsyncMock) as connect:
            connect.return_value = (Mock(), writer)
            await client.connect()
        connect.assert_awaited_once_with("192.0.2.20", 5061, ssl=None)
        self.assertEqual(client.media_ip, "192.0.2.10")

    async def test_invite_advertises_receiver_not_gateway(self):
        client, writer = self.make_client()
        client._writer = writer
        client._registered = True
        client._send_recv = AsyncMock(return_value="SIP/2.0 200 OK\r\nTo: <sip:test>;tag=peer\r\n\r\n")
        await client.initiate_video_call("sip:c300x@example.invalid", 9000, "20")
        request = client._send_recv.call_args.args[0]
        sdp = request.split("\r\n\r\n", 1)[1]
        self.assertIn("IN IP4 192.0.2.10\r\n", sdp)
        self.assertIn("c=IN IP4 192.0.2.10\r\n", sdp)
        self.assertNotIn("192.0.2.20", sdp)
        self.assertIn("a=DEVADDR:20\r\n", sdp)
        self.assertIn("m=video 9000 RTP/AVP 99\r\n", sdp)
        body_size = len(sdp.encode())
        self.assertIn(f"Content-Length: {body_size}\r\n", request)

    async def test_missing_or_invalid_socket_address_fails_before_invite(self):
        for sockname in (None, (), ("::1", 45000), ("0.0.0.0", 45000)):
            with self.subTest(sockname=sockname):
                client, writer = self.make_client(sockname)
                client._writer = writer
                client._registered = True
                client._send_recv = AsyncMock()
                with self.assertRaises(sip.BticinoSipError):
                    await client.initiate_video_call("sip:c300x@example.invalid", 9000)
                client._send_recv.assert_not_awaited()
        client, _ = self.make_client()
        with self.assertRaises(sip.BticinoSipError):
            _ = client.media_ip

    async def test_camera_passes_receiver_address_to_ffmpeg(self):
        # Exercise the actual camera startup method without importing HA.
        source = ast.parse((ROOT / "camera.py").read_text())
        camera_class = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == "BticinoCamera")
        startup = next(node for node in camera_class.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "_start_video")
        namespace = {
            "BticinoSipClient": Mock(), "SipCredentials": Mock(), "TlsCertificates": Mock(),
            "SIP_TLS_PORT": 5061, "_RTP_PORT_MIN": 9000, "_RTP_PORT_MAX": 9099,
            "random": Mock(), "_LOGGER": Mock(),
        }
        namespace["random"].randint.return_value = 9000
        client = Mock()
        client.media_ip = "192.0.2.10"
        client.connect = AsyncMock()
        client.initiate_video_call = AsyncMock(return_value=Mock())
        namespace["BticinoSipClient"].return_value = client
        exec(compile(ast.Module(body=[startup], type_ignores=[]), "camera.py", "exec"), namespace)
        camera = Mock()
        camera._sip_params = {
            "local_ip": "192.0.2.20", "sip_domain": "example.invalid",
            "sip_username": "test", "sip_password": "test",
        }
        camera._devaddr = "20"
        camera._start_ffmpeg = AsyncMock()
        await namespace["_start_video"](camera)
        self.assertEqual(namespace["BticinoSipClient"].call_args.kwargs["local_ip"], "192.0.2.20")
        camera._start_ffmpeg.assert_awaited_once_with(9000, "192.0.2.10", 99)


if __name__ == "__main__":
    unittest.main()

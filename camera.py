"""Camera entity for Bticino C300X — on-demand H.264 video via SIP INVITE."""

from __future__ import annotations

import asyncio
import logging
import os
import random
import tempfile
from typing import Optional

from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo as HaDeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .bticino_lib import BticinoSipClient, VideoCallSession
from .bticino_lib.models import SipCredentials, TlsCertificates
from .bticino_lib.const import SIP_TLS_PORT
from .const import DATA_OWN_PARAMS, DATA_SIP_PARAMS, DOMAIN

_LOGGER = logging.getLogger(__name__)

_INACTIVITY_TIMEOUT = 30   # seconds without image request → stop stream
_FFMPEG_FPS = 5
_RTP_PORT_MIN = 9000
_RTP_PORT_MAX = 9099


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    sip = data[DATA_SIP_PARAMS]
    if not sip.get("sip_username") or not sip.get("sip_domain"):
        _LOGGER.warning("Bticino camera: SIP not configured — camera disabled")
        return
    async_add_entities([BticinoCamera(data[DATA_OWN_PARAMS], sip, entry.entry_id)])


class BticinoCamera(Camera):
    """On-demand video camera: opens a SIP INVITE when the feed is first accessed,
    pipes H.264 RTP through ffmpeg, serves MJPEG frames, closes after inactivity."""

    _attr_has_entity_name = True
    _attr_name = "Videocitofono"
    _attr_icon = "mdi:doorbell-video"

    def __init__(self, own_params: dict, sip_params: dict, entry_id: str) -> None:
        super().__init__()
        self._own_params = own_params
        self._sip_params = sip_params
        self._attr_unique_id = f"{entry_id}_camera"

        self._sip_client: Optional[BticinoSipClient] = None
        self._video_session: Optional[VideoCallSession] = None
        self._ffmpeg_proc: Optional[asyncio.subprocess.Process] = None
        self._sdp_path: Optional[str] = None
        self._frame_task: Optional[asyncio.Task] = None
        self._latest_frame: Optional[bytes] = None
        self._inactivity_cancel: Optional[asyncio.TimerHandle] = None
        self._start_lock = asyncio.Lock()

    @property
    def device_info(self) -> HaDeviceInfo:
        return HaDeviceInfo(
            identifiers={(DOMAIN, self._own_params["gateway_id"])},
            name="Bticino C300X",
            manufacturer="Bticino / Legrand",
            model="C300X",
        )

    # ------------------------------------------------------------------
    # Camera API
    # ------------------------------------------------------------------

    async def async_camera_image(
        self, width: Optional[int] = None, height: Optional[int] = None
    ) -> Optional[bytes]:
        self._reset_inactivity_timer()
        async with self._start_lock:
            if self._ffmpeg_proc is None or self._ffmpeg_proc.returncode is not None:
                await self._start_video()
        return self._latest_frame

    async def async_will_remove_from_hass(self) -> None:
        await self._stop_video()

    # ------------------------------------------------------------------
    # Inactivity timer
    # ------------------------------------------------------------------

    def _reset_inactivity_timer(self) -> None:
        if self._inactivity_cancel is not None:
            self._inactivity_cancel()
            self._inactivity_cancel = None

        @callback
        def _on_inactive(_now: object) -> None:
            self._inactivity_cancel = None
            self.hass.async_create_task(self._stop_video())

        self._inactivity_cancel = async_call_later(
            self.hass, _INACTIVITY_TIMEOUT, _on_inactive
        )

    # ------------------------------------------------------------------
    # Video lifecycle
    # ------------------------------------------------------------------

    async def _start_video(self) -> None:
        sip = self._sip_params
        local_ip = sip.get("local_ip", "")
        sip_domain = sip.get("sip_domain", "")
        target = f"sip:c300x@{sip_domain}"
        local_rtp_port = random.randint(_RTP_PORT_MIN, _RTP_PORT_MAX)

        creds = SipCredentials(
            username=sip["sip_username"],
            password=sip["sip_password"],
            domain=sip_domain,
        )
        tls = TlsCertificates(
            ca_cert_pem=sip.get("tls_ca_cert", ""),
            client_cert_pem=sip.get("tls_client_cert", ""),
            client_key_pem=sip.get("tls_client_key", ""),
        )

        client = BticinoSipClient(
            credentials=creds, tls=tls, local_ip=local_ip,
            sip_port=SIP_TLS_PORT, use_tls=True,
        )
        try:
            await client.connect()
            session = await client.initiate_video_call(target, local_rtp_port)
        except Exception as exc:
            _LOGGER.error("Camera: SIP INVITE failed: %s", exc)
            try:
                await client.close()
            except Exception:
                pass
            return

        self._sip_client = client
        self._video_session = session

        # SDP file for ffmpeg so it knows the codec / port to listen on
        sdp = (
            "v=0\r\n"
            f"o=- 0 0 IN IP4 {local_ip}\r\n"
            "s=bticino\r\n"
            f"c=IN IP4 {local_ip}\r\n"
            "t=0 0\r\n"
            f"m=video {local_rtp_port} RTP/AVP 96\r\n"
            "a=rtpmap:96 H264/90000\r\n"
        )
        fd, sdp_path = tempfile.mkstemp(suffix=".sdp", prefix="bticino_")
        try:
            os.write(fd, sdp.encode())
        finally:
            os.close(fd)
        self._sdp_path = sdp_path

        try:
            self._ffmpeg_proc = await asyncio.create_subprocess_exec(
                "ffmpeg",
                "-loglevel", "error",
                "-protocol_whitelist", "file,rtp,udp",
                "-i", sdp_path,
                "-vf", f"fps={_FFMPEG_FPS}",
                "-q:v", "5",
                "-f", "image2pipe",
                "-vcodec", "mjpeg",
                "pipe:1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            _LOGGER.error("Camera: ffmpeg not found — install ffmpeg on the HA host")
            await self._stop_video()
            return
        except Exception as exc:
            _LOGGER.error("Camera: ffmpeg start failed: %s", exc)
            await self._stop_video()
            return

        self._frame_task = self.hass.async_create_background_task(
            self._read_frames(), name="bticino_camera_frames"
        )
        _LOGGER.info("Camera: stream started (RTP port %d)", local_rtp_port)

    async def _stop_video(self) -> None:
        if self._inactivity_cancel is not None:
            self._inactivity_cancel()
            self._inactivity_cancel = None

        if self._frame_task and not self._frame_task.done():
            self._frame_task.cancel()
            try:
                await self._frame_task
            except (asyncio.CancelledError, Exception):
                pass
        self._frame_task = None

        if self._ffmpeg_proc is not None:
            try:
                self._ffmpeg_proc.terminate()
                await asyncio.wait_for(self._ffmpeg_proc.wait(), timeout=5.0)
            except Exception:
                try:
                    self._ffmpeg_proc.kill()
                except Exception:
                    pass
            self._ffmpeg_proc = None

        if self._sdp_path:
            try:
                os.unlink(self._sdp_path)
            except OSError:
                pass
            self._sdp_path = None

        if self._sip_client and self._video_session:
            try:
                await self._sip_client.hang_up(self._video_session)
            except Exception as exc:
                _LOGGER.debug("Camera: BYE error: %s", exc)

        if self._sip_client:
            try:
                await self._sip_client.close()
            except Exception:
                pass
            self._sip_client = None

        self._video_session = None
        self._latest_frame = None
        _LOGGER.info("Camera: stream stopped")

    async def _read_frames(self) -> None:
        """Parse MJPEG stream from ffmpeg stdout (FF D8 … FF D9 boundaries)."""
        proc = self._ffmpeg_proc
        if proc is None or proc.stdout is None:
            return
        buf = b""
        try:
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                buf += chunk
                while True:
                    start = buf.find(b"\xff\xd8")
                    if start == -1:
                        buf = b""
                        break
                    end = buf.find(b"\xff\xd9", start + 2)
                    if end == -1:
                        buf = buf[start:]
                        break
                    self._latest_frame = buf[start : end + 2]
                    buf = buf[end + 2 :]
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            _LOGGER.debug("Camera: frame reader error: %s", exc)

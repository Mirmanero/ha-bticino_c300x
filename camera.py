"""Camera entity for Bticino C300X — video from incoming SIP INVITE (doorbell ring).

The C300X gateway sends a SIP INVITE when someone rings the doorbell.
BticinoSipListener accepts it with 200 OK + SDP and calls on_video_start(),
which starts ffmpeg to receive H.264 RTP and extract MJPEG frames.
The camera entity serves the latest frame via async_camera_image().
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from typing import Optional

from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo as HaDeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DATA_DOORBELL_LISTENER, DATA_OWN_PARAMS, DATA_SIP_PARAMS, DOMAIN

_LOGGER = logging.getLogger(__name__)

_FFMPEG_FPS = 5


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
    async_add_entities([BticinoCamera(data[DATA_OWN_PARAMS], entry.entry_id)])


class BticinoCamera(Camera):
    """Camera that shows live H.264 video during an incoming doorbell SIP call.

    The SIP listener accepts the INVITE and calls our on_video_start() callback.
    ffmpeg receives the RTP stream and we extract MJPEG frames for HA.
    After the gateway sends BYE, on_video_end() stops ffmpeg; the last frame
    remains visible until the next call.
    """

    _attr_has_entity_name = True
    _attr_name = "Videocitofono"
    _attr_icon = "mdi:doorbell-video"

    def __init__(self, own_params: dict, entry_id: str) -> None:
        super().__init__()
        self._own_params = own_params
        self._entry_id = entry_id
        self._attr_unique_id = f"{entry_id}_camera"

        self._ffmpeg_proc: Optional[asyncio.subprocess.Process] = None
        self._sdp_path: Optional[str] = None
        self._frame_task: Optional[asyncio.Task] = None
        self._latest_frame: Optional[bytes] = None

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
        return self._latest_frame

    async def async_added_to_hass(self) -> None:
        listener = (
            self.hass.data.get(DOMAIN, {})
            .get(self._entry_id, {})
            .get(DATA_DOORBELL_LISTENER)
        )
        if listener is not None:
            listener.set_video_callbacks(self.on_video_start, self.on_video_end)
            _LOGGER.debug("Camera: video callbacks registered with SIP listener")
        else:
            _LOGGER.warning("Camera: SIP listener not available — no video")

    async def async_will_remove_from_hass(self) -> None:
        listener = (
            self.hass.data.get(DOMAIN, {})
            .get(self._entry_id, {})
            .get(DATA_DOORBELL_LISTENER)
        )
        if listener is not None:
            listener.set_video_callbacks(None, None)
        await self._stop_ffmpeg()

    # ------------------------------------------------------------------
    # Callbacks from SIP listener
    # ------------------------------------------------------------------

    async def on_video_start(self, rtp_port: int, local_ip: str, video_pt: int) -> None:
        """Called by the SIP listener after accepting the INVITE with 200 OK.
        Start ffmpeg before we return so the port is ready when RTP arrives."""
        await self._stop_ffmpeg()

        sdp = (
            "v=0\r\n"
            f"o=- 0 0 IN IP4 {local_ip}\r\n"
            "s=bticino\r\n"
            f"c=IN IP4 {local_ip}\r\n"
            "t=0 0\r\n"
            f"m=video {rtp_port} RTP/AVP {video_pt}\r\n"
            f"a=rtpmap:{video_pt} H264/90000\r\n"
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
            self._cleanup_sdp()
            raise
        except Exception as exc:
            _LOGGER.error("Camera: ffmpeg start failed: %s", exc)
            self._cleanup_sdp()
            raise

        self._frame_task = self.hass.async_create_background_task(
            self._read_frames(), name="bticino_camera_frames"
        )
        _LOGGER.info("Camera: stream started (RTP port %d, PT %d)", rtp_port, video_pt)

    def on_video_end(self) -> None:
        """Called by the SIP listener when BYE is received."""
        _LOGGER.info("Camera: call ended (BYE) — stopping stream")
        self.hass.async_create_task(self._stop_ffmpeg())

    # ------------------------------------------------------------------
    # ffmpeg lifecycle
    # ------------------------------------------------------------------

    async def _stop_ffmpeg(self) -> None:
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

        self._cleanup_sdp()
        _LOGGER.debug("Camera: ffmpeg stopped")

    def _cleanup_sdp(self) -> None:
        if self._sdp_path:
            try:
                os.unlink(self._sdp_path)
            except OSError:
                pass
            self._sdp_path = None

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

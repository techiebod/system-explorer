"""Thin wrapper over dbus-fast for read-only system-bus observation.

Adapters depend on this module, not on dbus-fast directly (an early design risk
control: a library swap touches one file). Only read patterns exist here —
GetAll, Get, and argument-carrying reads like LoadUnit; nothing in this
module can mutate operating-system state.
"""

from __future__ import annotations

import asyncio
from typing import Any

from dbus_fast import BusType, Message, MessageType, Variant
from dbus_fast.aio import MessageBus

SYSTEMD = "org.freedesktop.systemd1"
SYSTEMD_PATH = "/org/freedesktop/systemd1"
SYSTEMD_MANAGER = "org.freedesktop.systemd1.Manager"
HOSTNAME1 = "org.freedesktop.hostname1"
TIMEDATE1 = "org.freedesktop.timedate1"
PROPERTIES = "org.freedesktop.DBus.Properties"


def unwrap(value: Any) -> Any:
    if isinstance(value, Variant):
        return unwrap(value.value)
    if isinstance(value, dict):
        return {k: unwrap(v) for k, v in value.items()}
    # dbus-fast yields STRUCT values as tuples; without recursing them, bytes
    # nested inside (e.g. resolve1's (iiay) DNS entries) reach the JSON
    # serializer raw and 500 the response.
    if isinstance(value, (list, tuple)):
        return [unwrap(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        # 'ay' properties (e.g. Service StandardInputData) are not JSON;
        # base64 keeps evidence payloads lossless and serialisable.
        import base64
        return {"__bytes_base64__": base64.b64encode(bytes(value)).decode("ascii")}
    return value


class CallError(RuntimeError):
    """A D-Bus method call returned an error reply. The error name is kept
    structured because for some services it *is* the answer — resolve1
    returns NXDOMAIN and friends this way."""

    def __init__(self, interface: str, member: str, error_name: str | None, body: Any) -> None:
        self.error_name = error_name or "unknown-error"
        super().__init__(f"{interface}.{member} failed: {error_name}: {body}")


class SystemBus:
    def __init__(self) -> None:
        self._bus: MessageBus | None = None
        self._lock = asyncio.Lock()

    async def _get(self) -> MessageBus:
        async with self._lock:
            if self._bus is None or not self._bus.connected:
                self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            return self._bus

    async def call(self, destination: str, path: str, interface: str, member: str,
                   signature: str = "", body: list | None = None) -> list:
        bus = await self._get()
        reply = await bus.call(Message(
            destination=destination, path=path, interface=interface,
            member=member, signature=signature, body=body or [],
        ))
        if reply.message_type == MessageType.ERROR:
            raise CallError(interface, member, reply.error_name, reply.body)
        return unwrap(reply.body)

    async def get_all(self, destination: str, path: str, interface: str) -> dict:
        body = await self.call(destination, path, PROPERTIES, "GetAll", "s", [interface])
        return body[0]


BUS = SystemBus()

"""Tehlikeli komutlar icin zorlayici onay kapisi.

DeerFlow'da iki sey zaten var: dar bir sert-blok listesi (SandboxAudit,
~15 desen, sorulmadan engeller) ve prompt seviyesinde bir temenni
(`ask_clarification`). Eksik olan, genis kapsamli tespit + kullaniciya
secim sunan katmandi. Bu middleware onu ekler.

Kapi araç çağrısını gercekten keser: `handler(request)` cagrilmazsa komut
hicbir zaman calismaz.

MODLAR (AGENT_GUARD_MODE):
  manual  Her tehlikeli komutta kullaniciya sorar. Varsayilan.
  auto    Yardimci bir model gercek riski degerlendirir; zararsizlari
          gecirir, riskliyi engeller, emin olamazsa kullaniciya sorar.
  off     Kapi devre disi.

TABAN KATMANI moddan bagimsizdir: geri alinamaz komutlar auto modda bile
yargica sorulmadan dogrudan kullaniciya gider ve kalici izne baglanamaz.

Cekirdege dokunmaz; config.yaml icinde su sekilde baglanir:

    extensions:
      middlewares:
        - agent_guard.middleware:ApprovalGateMiddleware
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.graph import END
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from agent_guard.card import (
    APPROVE_OPTIONS,
    OPTION_DENY,
    OPTION_ONCE,
    OPTION_SESSION,
    SOURCE,
    build_card,
    find_decision,
    request_id_for,
)
from agent_guard.detect import Finding, detect
from agent_guard.judge import VERDICT_APPROVE, VERDICT_DENY, assess

logger = logging.getLogger(__name__)

GATED_TOOLS = frozenset({"bash"})
COMMAND_ARG_NAMES = ("command", "cmd", "script")

MODE_ENV_VAR = "AGENT_GUARD_MODE"
MODE_MANUAL = "manual"
MODE_AUTO = "auto"
MODE_OFF = "off"
VALID_MODES = (MODE_MANUAL, MODE_AUTO, MODE_OFF)
DEFAULT_MODE = MODE_MANUAL

_NL = chr(10)

_DENIED_TEMPLATE = _NL.join([
    "REDDEDILDI: Kullanici bu komutu calistirmani onaylamadi.",
    "",
    "Komut: {command}",
    "",
    "Ayni komutu tekrar deneme. Baska bir yol oner ya da kullaniciya neye",
    "ihtiyacin oldugunu sor.",
])

_JUDGE_DENIED_TEMPLATE = _NL.join([
    "ENGELLENDI: Guvenlik degerlendirmesi bu komutu riskli buldu ({description}).",
    "",
    "Komut: {command}",
    "",
    "Komut CALISTIRILMADI. Daha dar kapsamli, geri alinabilir bir yol oner",
    "ya da kullanicidan acik onay iste.",
])

_CARD_TEXT_TEMPLATE = _NL.join([
    "Onay bekleniyor: {description}",
    "",
    "Komut: {command}",
    "",
    "Bu komut tehlikeli olarak siniflandirildi ve CALISTIRILMADI.",
    "Kullanicinin karari bekleniyor.",
])


def _current_mode() -> str:
    """Onay modunu ortam degiskeninden oku.

    Her cagrida okunur; boylece mod degisikligi ajani yeniden kurmadan ve
    sistem prompt'una dokunmadan etkili olur (prompt cache korunur).
    Tanimsiz veya gecersiz deger guvenli tarafa, 'manual'a duser.
    """
    mode = (os.environ.get(MODE_ENV_VAR) or DEFAULT_MODE).strip().lower()
    return mode if mode in VALID_MODES else DEFAULT_MODE


class ApprovalGateMiddleware(AgentMiddleware):
    """Tehlikeli kabuk komutlarini kullanici onaylamadan calistirmaz."""

    def __init__(self, gated_tools: frozenset[str] | None = None, *, judge=None) -> None:
        super().__init__()
        self._gated_tools = gated_tools or GATED_TOOLS
        self._judge = judge or assess
        self._lock = threading.Lock()
        # 'Bir kez onayla' kararlarinin tuketildigi kayit. Surec omru boyunca
        # gecerlidir; gateway yeniden baslarsa sifirlanir ve kullaniciya
        # yeniden sorulur (guvenli taraf).
        self._consumed_once: set[str] = set()

    # -- yardimcilar ----------------------------------------------------

    @staticmethod
    def _extract_command(tool_call: dict[str, Any]) -> str | None:
        args = tool_call.get("args") or {}
        if not isinstance(args, dict):
            return None
        for key in COMMAND_ARG_NAMES:
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return None

    def _consume_once(self, request_id: str) -> bool:
        """'Bir kez' karari henuz kullanilmadiysa tuket ve True dondur."""
        with self._lock:
            if request_id in self._consumed_once:
                return False
            self._consumed_once.add(request_id)
            return True

    def _blocked(self, content: str, tool_call: dict[str, Any]) -> ToolMessage:
        return ToolMessage(
            content=content,
            tool_call_id=str(tool_call.get("id", "")),
            name=str(tool_call.get("name", "")),
            status="error",
        )

    def _ask(self, command: str, finding: Finding, tool_call: dict[str, Any]) -> Command:
        """Onay kartini goster ve turu bitir."""
        seviye = "TABAN" if finding.hardline else "tehlikeli"
        logger.warning("agent_guard: onay bekleniyor [%s] (%s): %s", seviye, finding.description, command[:200])
        tool_call_id = str(tool_call.get("id", ""))
        card = build_card(
            command=command,
            description=finding.description or "",
            tool_call_id=tool_call_id,
            hardline=finding.hardline,
        )
        message = ToolMessage(
            id=request_id_for(command),
            content=_CARD_TEXT_TEMPLATE.format(description=finding.description, command=command),
            tool_call_id=tool_call_id,
            name=str(tool_call.get("name", "")),
            status="error",
            artifact={"human_input": card},
        )
        return Command(update={"messages": [message]}, goto=END)

    def _decide(self, request: ToolCallRequest) -> ToolMessage | Command | None:
        """Engelleme/karti dondur; komut calisabilecekse None dondur."""
        tool_call = request.tool_call or {}
        if tool_call.get("name") not in self._gated_tools:
            return None

        mode = _current_mode()
        if mode == MODE_OFF:
            return None

        command = self._extract_command(tool_call)
        if command is None:
            return None

        finding = detect(command)
        if not finding:
            return None

        # 1) Kullanicinin bu komut icin verdigi onceki karar
        decision = find_decision(request.state, command)
        request_id = request_id_for(command)

        if decision == OPTION_DENY:
            logger.warning("agent_guard: kullanici reddetti: %s", command[:200])
            return self._blocked(_DENIED_TEMPLATE.format(command=command), tool_call)

        if decision in APPROVE_OPTIONS:
            if finding.hardline and decision == OPTION_SESSION:
                # Taban katmaninda oturum izni gecersizdir.
                logger.warning("agent_guard: taban katmaninda oturum izni yok sayildi")
            elif decision == OPTION_ONCE and not self._consume_once(request_id):
                logger.info("agent_guard: 'bir kez' karari tukenmis, yeniden soruluyor")
            else:
                logger.info("agent_guard: kullanici onayladi (%s): %s", decision, command[:200])
                return None

        # 2) Auto mod: taban DISINDAKI komutlar icin yardimci modele sor.
        #    Taban katmani bilerek atlanir -- geri alinamaz bir islem asla
        #    otomatik onaylanmamalidir.
        if mode == MODE_AUTO and not finding.hardline:
            verdict = self._judge(command, finding.description or "")
            if verdict == VERDICT_APPROVE:
                logger.info("agent_guard: auto onay: %s", command[:200])
                return None
            if verdict == VERDICT_DENY:
                return self._blocked(
                    _JUDGE_DENIED_TEMPLATE.format(description=finding.description, command=command),
                    tool_call,
                )
            # ESCALATE ya da anlasilmayan cevap: kullaniciya sor.

        # 3) Karar yok: onay kartini goster.
        return self._ask(command, finding, tool_call)

    # -- middleware arayuzu ---------------------------------------------

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command],
    ) -> ToolMessage | Command:
        blocked = self._decide(request)
        if blocked is not None:
            return blocked
        return handler(request)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command]],
    ) -> ToolMessage | Command:
        blocked = self._decide(request)
        if blocked is not None:
            return blocked
        return await handler(request)


__all__ = ["ApprovalGateMiddleware", "MODE_AUTO", "MODE_MANUAL", "MODE_OFF", "SOURCE"]

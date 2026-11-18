"""Onay kartinin insa edilmesi ve kullanici kararinin geri okunmasi.

DeerFlow'un frontend'i, bir ToolMessage'in artifact'inda
``{"human_input": {...}}`` gorunce onu etkilesimli bir kart olarak cizer.
Sema ``frontend/src/core/messages/human-input.ts`` icinde tanimli ve
``source`` alani herhangi bir dizeyi kabul eder. Bu sayede kendi kartimizi
frontend'e hic dokunmadan gonderebiliyoruz.
"""

from __future__ import annotations

import hashlib
from typing import Any

SOURCE = "agent_guard"

OPTION_ONCE = "approve_once"
OPTION_SESSION = "approve_session"
OPTION_DENY = "deny"

APPROVE_OPTIONS = frozenset({OPTION_ONCE, OPTION_SESSION})


def decision_key(command: str) -> str:
    """Komuta karsilik gelen kararli kimlik."""
    return hashlib.sha256(command.strip().encode("utf-8")).hexdigest()[:16]


def request_id_for(command: str) -> str:
    return f"{SOURCE}:{decision_key(command)}"


def build_card(
    *,
    command: str,
    description: str,
    tool_call_id: str,
    hardline: bool = False,
) -> dict[str, Any]:
    """Onay kartinin human_input yukunu uret.

    input_mode 'single_choice' oldugu icin options en az bir oge icermeli ve
    id/value degerleri benzersiz olmalidir; aksi halde frontend yuku reddeder
    ve kart hic cizilmez.

    hardline=True ise kalici izin secenegi BILEREK sunulmaz: taban
    katmanindaki komutlar geri alinamaz oldugu icin her denemede yeniden
    sorulmalidir.
    """
    key = decision_key(command)

    options: list[dict[str, str]] = [
        {"id": OPTION_ONCE, "label": "Bir kez onayla", "value": f"{SOURCE}-once-{key}"}
    ]
    if not hardline:
        options.append(
            {"id": OPTION_SESSION, "label": "Bu sohbette hep onayla", "value": f"{SOURCE}-session-{key}"}
        )
    options.append({"id": OPTION_DENY, "label": "Reddet", "value": f"{SOURCE}-deny-{key}"})

    newline = chr(10)
    if hardline:
        title = "GERI ALINAMAZ islem onayi"
        question = f"Ajan geri alinamaz bir islem yapmak istiyor: {description}"
        context = (
            f"Komut:{newline}{command}{newline}{newline}"
            "Bu islem geri alinamaz. Kalici izin verilemez; her denemede yeniden sorulur."
        )
    else:
        title = "Tehlikeli komut onayi"
        question = f"Ajan tehlikeli bir komut calistirmak istiyor: {description}"
        context = f"Komut:{newline}{command}"

    return {
        "version": 1,
        "kind": "human_input_request",
        "source": SOURCE,
        "request_id": f"{SOURCE}:{key}",
        "tool_call_id": tool_call_id,
        "title": title,
        "question": question,
        "context": context,
        "input_mode": "single_choice",
        "options": options,
    }


def _iter_messages(state: Any):
    messages = state.get("messages") if isinstance(state, dict) else getattr(state, "messages", None)
    return reversed(messages) if messages else iter(())


def find_decision(state: Any, command: str) -> str | None:
    """Bu komut icin kullanicinin verdigi son karari dondur.

    Donus: OPTION_ONCE / OPTION_SESSION / OPTION_DENY veya karar yoksa None.
    Mesaj gecmisi tersten taranir, boylece en son karar kazanir.
    """
    target = request_id_for(command)
    for message in _iter_messages(state):
        kwargs = getattr(message, "additional_kwargs", None) or {}
        response = kwargs.get("human_input_response")
        if not isinstance(response, dict):
            continue
        if response.get("source") != SOURCE:
            continue
        if response.get("request_id") != target:
            continue
        option_id = response.get("option_id")
        if isinstance(option_id, str) and option_id:
            return option_id
    return None


def session_approved(state: Any, command: str) -> bool:
    """Bu komut icin 'bu sohbette hep onayla' secilmis mi."""
    return find_decision(state, command) == OPTION_SESSION

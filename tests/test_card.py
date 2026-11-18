"""Onay karti testleri.

Sema dogrulamasi, frontend'deki parseHumanInputRequest kurallarini birebir
yansitir (frontend/src/core/messages/human-input.ts). Kart bu kurallardan
birini ihlal ederse frontend yuku sessizce reddeder ve kart hic cizilmez --
kullanici hicbir sey gormez ama komut da calismaz. Bu yuzden sozlesmeyi
burada kilitliyoruz.
"""

import pytest

from agent_guard.card import (
    OPTION_DENY,
    OPTION_ONCE,
    OPTION_SESSION,
    SOURCE,
    build_card,
    decision_key,
    find_decision,
    request_id_for,
)

GECERLI_MODLAR = {"free_text", "single_choice", "choice_with_other", "form"}


class SahteMesaj:
    def __init__(self, kwargs=None):
        self.additional_kwargs = kwargs or {}


def yanit(option_id, command, source=SOURCE):
    return SahteMesaj({
        "human_input_response": {
            "version": 1,
            "kind": "human_input_response",
            "source": source,
            "request_id": request_id_for(command),
            "response_kind": "option",
            "option_id": option_id,
            "value": "x",
        }
    })


@pytest.fixture
def kart():
    return build_card(command="rm -rf /", description="delete in root path", tool_call_id="tc-1")


def test_zorunlu_alanlar_var(kart):
    assert kart["version"] in (1, 2)
    assert kart["kind"] == "human_input_request"
    assert isinstance(kart["source"], str) and kart["source"]
    assert isinstance(kart["request_id"], str) and kart["request_id"]
    assert isinstance(kart["question"], str) and kart["question"]
    assert kart["input_mode"] in GECERLI_MODLAR


def test_single_choice_en_az_bir_secenek_ister(kart):
    """input_mode single_choice ise options bos olamaz, yoksa frontend reddeder."""
    assert kart["input_mode"] == "single_choice"
    assert len(kart["options"]) >= 1


def test_secenek_id_ve_value_benzersiz(kart):
    ids = [o["id"] for o in kart["options"]]
    values = [o["value"] for o in kart["options"]]
    assert len(ids) == len(set(ids)), "secenek id'leri benzersiz olmali"
    assert len(values) == len(set(values)), "secenek value'lari benzersiz olmali"


def test_secenekler_tam_sema(kart):
    for o in kart["options"]:
        assert set(o) >= {"id", "label", "value"}
        assert all(isinstance(o[k], str) and o[k] for k in ("id", "label", "value"))


def test_form_modu_degil_yani_v1_olmali(kart):
    """Frontend kurali: (input_mode == 'form') ile (version == 2) ayni olmali."""
    assert (kart["input_mode"] == "form") == (kart["version"] == 2)


def test_komut_baglamda_gorunur(kart):
    assert "rm -rf /" in kart["context"]


def test_ayni_komut_ayni_kimlik():
    assert decision_key("rm -rf /") == decision_key("rm -rf /")
    assert decision_key("  rm -rf /  ") == decision_key("rm -rf /")


def test_farkli_komut_farkli_kimlik():
    assert decision_key("rm -rf /") != decision_key("rm -rf /tmp")


# -- karar okuma -------------------------------------------------------

def test_karar_yoksa_none():
    assert find_decision({"messages": []}, "rm -rf /") is None


def test_onay_okunur():
    state = {"messages": [yanit(OPTION_ONCE, "rm -rf /")]}
    assert find_decision(state, "rm -rf /") == OPTION_ONCE


def test_ret_okunur():
    state = {"messages": [yanit(OPTION_DENY, "rm -rf /")]}
    assert find_decision(state, "rm -rf /") == OPTION_DENY


def test_baska_komutun_karari_sizmaz():
    """Bir komutun onayi baska bir komutu onaylamamali."""
    state = {"messages": [yanit(OPTION_SESSION, "rm -rf /tmp")]}
    assert find_decision(state, "rm -rf /") is None


def test_baska_kaynagin_karari_sayilmaz():
    """ask_clarification yaniti bizim onayimiz yerine gecmemeli."""
    state = {"messages": [yanit(OPTION_ONCE, "rm -rf /", source="ask_clarification")]}
    assert find_decision(state, "rm -rf /") is None


def test_en_son_karar_kazanir():
    state = {"messages": [
        yanit(OPTION_DENY, "rm -rf /"),
        yanit(OPTION_SESSION, "rm -rf /"),
    ]}
    assert find_decision(state, "rm -rf /") == OPTION_SESSION

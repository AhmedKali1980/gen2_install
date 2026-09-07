import csv
import importlib
import sys
import types
import re
from pathlib import Path


def _load_module(monkeypatch):
    illumio = types.ModuleType("illumio")
    illumio.PairingProfile = object
    illumio.PolicyComputeEngine = object
    iamaas = types.ModuleType("sg_iamaas")
    iamaas.CachingTokenGenerator = object
    openpyxl = types.ModuleType("openpyxl")
    openpyxl.Workbook = object
    openpyxl_cell = types.ModuleType("openpyxl.cell")
    openpyxl_cell_cell = types.ModuleType("openpyxl.cell.cell")
    openpyxl_cell_cell.ILLEGAL_CHARACTERS_RE = re.compile(r"[\x00-\x08]")
    requests = types.ModuleType("requests")
    config = types.ModuleType("config")
    config.OSC_API_URL = "https://osc.example.test"
    utils = types.ModuleType("utils")
    utils.get_pce_connection = lambda *args: None
    monkeypatch.setitem(sys.modules, "illumio", illumio)
    monkeypatch.setitem(sys.modules, "sg_iamaas", iamaas)
    monkeypatch.setitem(sys.modules, "openpyxl", openpyxl)
    monkeypatch.setitem(sys.modules, "openpyxl.cell", openpyxl_cell)
    monkeypatch.setitem(sys.modules, "openpyxl.cell.cell", openpyxl_cell_cell)
    monkeypatch.setitem(sys.modules, "requests", requests)
    monkeypatch.setitem(sys.modules, "config", config)
    monkeypatch.setitem(sys.modules, "utils", utils)
    sys.modules.pop("gen2_bulk_install", None)
    module_path = Path(__file__).parents[1] / "gen2_bulk_install.py"
    spec = importlib.util.spec_from_file_location("gen2_bulk_install", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_uninstall_accepts_minimal_csv_and_ignores_blank_lines(tmp_path, monkeypatch):
    module = _load_module(monkeypatch)
    source = tmp_path / "servers.csv"
    source.write_text(
        "server_id;account_id;osc_api_url\n"
        "server-1;account-1;\n"
        ";;\n"
        "   ; ; \n"
        "server-2;account-2;\n",
        encoding="utf-8",
    )

    output, delimiter = module.create_output_csv_with_extra_columns(
        str(source), "prd", False, "uninstall"
    )

    with open(output, newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream, delimiter=delimiter))
    assert len(rows) == 3
    assert rows[0][-5:] == [
        "error", "uninstall_job_id", "uninstall_status",
        "association_status", "dissociation_status",
    ]


def test_uninstall_payload_only_requests_absent(monkeypatch):
    module = _load_module(monkeypatch)
    assert module.build_osc_uninstall_payload() == {
        "modules": [{"name": "sg_illumio_ven", "params": {"ensure": "absent"}}]
    }


def test_help_lists_required_columns_for_each_operation(monkeypatch):
    module = _load_module(monkeypatch)

    help_text = module._build_argument_parser().format_help()

    assert "--uninstall" in help_text
    assert "Install:   server_id, account_id, osc_api_url" in help_text
    assert "Uninstall: server_id, account_id, osc_api_url" in help_text
    assert "Blank or whitespace-only input rows are ignored." in help_text

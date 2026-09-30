"""Read ETS2 profiles. SII decoding follows sk-zk/TruckLib.Sii (MIT)."""
import ctypes
import json
import os
import re
import shutil
import tempfile
import zlib
from pathlib import Path
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.parse import urljoin

# Explicitly expose the bridge contract to the visual editor.  The editor can
# infer simple comparisons too, but declarations remain reliable if the
# dispatcher is refactored later.
SCS_ACTIONS = (
    "defaults",
    "scan_profiles",
    "read_mods",
    "load_presets",
    "apply_preset",
    "save_own_mods",
    "save_mod_order",
    "delete_backups",
    "set_save_format",
    "list_backups",
    "restore_backup",
    "prepare_verification",
    "verify_mod_files",
    "verify_mod_parameters",
    "verify_preset",
)
SCS_OUTPUT_IDS = ("status", "result")

AES_KEY = bytes.fromhex("2a5fcb1791d22fb60245b3d8369ed0b2c27371563fbf1f3c9edf6b11825a5d0a")
THREE_NK_TABLE = bytes.fromhex(
    "f8d1aa835c750e27b099e2cb143d466f68413a13cce59eb72009725b84add6ff"
    "d8f18aa37c552e0790b9c2eb341d664f48611a33ecc5be970029527ba48df6df"
    "b891eac31c354e67f0d9a28b547d062f28017a538ca5def76049321bc4ed96bf"
    "98b1cae33c156e47d0f982ab745d260f08215a73ac85fed74069123be4cdb69f"
    "78512a03dcf58ea73019624b94bdc6efe8c1ba934c651e37a089f2db042d567f"
    "58710a23fcd5ae871039426bb49de6cfc8e19ab36c453e1780a9d2fb240d765f"
    "38116a439cb5cee77059220bd4fd86afa881fad30c255e77e0c9b29b446d163f"
    "18314a63bc95eec75079022bf4dda68f88a1daf32c057e57c0e992bb644d361f"
)

def decrypt_aes_cbc(ciphertext, iv):
    """AES-256-CBC via Windows CryptoAPI; payload format is TruckLib.Sii's ScsC."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    provider = ctypes.c_void_p(); key = ctypes.c_void_p()
    if not advapi.CryptAcquireContextW(ctypes.byref(provider), None, None, 24, 0xF0000000):
        raise OSError(ctypes.get_last_error(), "CryptAcquireContextW failed")
    try:
        blob = b"\x08\x02\x00\x00\x10\x66\x00\x00" + len(AES_KEY).to_bytes(4, "little") + AES_KEY
        blob_data = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        if not advapi.CryptImportKey(provider, blob_data, len(blob), None, 0, ctypes.byref(key)):
            raise OSError(ctypes.get_last_error(), "CryptImportKey failed")
        iv_data = (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv)
        if not advapi.CryptSetKeyParam(key, 1, iv_data, 0):
            raise OSError(ctypes.get_last_error(), "CryptSetKeyParam failed")
        data = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext); size = ctypes.c_uint32(len(ciphertext))
        if not advapi.CryptDecrypt(key, None, True, 0, data, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "CryptDecrypt failed")
        return bytes(data[:size.value])
    finally:
        if key: advapi.CryptDestroyKey(key)
        if provider: advapi.CryptReleaseContext(provider, 0)

def encrypt_aes_cbc(plaintext, iv):
    """AES-256-CBC counterpart for ScsC profile output."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    provider = ctypes.c_void_p(); key = ctypes.c_void_p()
    if not advapi.CryptAcquireContextW(ctypes.byref(provider), None, None, 24, 0xF0000000):
        raise OSError(ctypes.get_last_error(), "CryptAcquireContextW failed")
    try:
        blob = b"\x08\x02\x00\x00\x10\x66\x00\x00" + len(AES_KEY).to_bytes(4, "little") + AES_KEY
        raw_key = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        if not advapi.CryptImportKey(provider, raw_key, len(blob), None, 0, ctypes.byref(key)): raise OSError(ctypes.get_last_error(), "CryptImportKey failed")
        raw_iv = (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv)
        if not advapi.CryptSetKeyParam(key, 1, raw_iv, 0): raise OSError(ctypes.get_last_error(), "CryptSetKeyParam failed")
        capacity = len(plaintext) + 32; data = (ctypes.c_ubyte * capacity)(); data[:len(plaintext)] = plaintext; size = ctypes.c_uint32(len(plaintext))
        if not advapi.CryptEncrypt(key, None, True, 0, data, ctypes.byref(size), capacity): raise OSError(ctypes.get_last_error(), "CryptEncrypt failed")
        return bytes(data[:size.value])
    finally:
        if key: advapi.CryptDestroyKey(key)
        if provider: advapi.CryptReleaseContext(provider, 0)

def storage_root():
    configured = os.environ.get("SCS_TOOL_RESOURCES", "").strip()
    root = Path(configured).expanduser() if configured else Path.cwd() / "tools_resources" / "Combo_Installer"
    root.mkdir(parents=True, exist_ok=True)
    return root

def save_resource_json(name, value):
    try: (storage_root() / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError: pass

def load_resource_json(name, default):
    try:
        value = json.loads((storage_root() / name).read_text(encoding="utf-8-sig"))
        return value
    except (OSError, json.JSONDecodeError):
        return default

def decode_sii(raw):
    if raw.startswith(b"SiiNunit"):
        decoded = raw
    elif raw.startswith(b"3nK") and len(raw) >= 6:
        seed = raw[5]; decoded = bytes(value ^ THREE_NK_TABLE[(seed + index) & 255] for index, value in enumerate(raw[6:]))
    elif raw.startswith(b"ScsC") and len(raw) >= 56:
        # Header: magic (4), HMAC (32), IV (16), size (uint32); exactly as TruckLib.Sii.
        decoded = zlib.decompress(decrypt_aes_cbc(raw[56:], raw[36:52]))
    else:
        raise ValueError("Unsupported SII format")
    return decoded.decode("utf-8-sig", errors="replace")

def profile_text(path):
    return decode_sii(path.read_bytes())

def unescape_sii_string(value):
    """Decode ETS2's escaped UTF-8 bytes (for example, \\xd0\\x9e)."""
    result = bytearray(); index = 0
    escapes = {"n": b"\n", "r": b"\r", "t": b"\t", "\\": b"\\", '"': b'"'}
    while index < len(value):
        if value[index] == "\\" and index + 3 < len(value) and value[index + 1] == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", value[index + 2:index + 4]):
            result.append(int(value[index + 2:index + 4], 16)); index += 4; continue
        if value[index] == "\\" and index + 1 < len(value) and value[index + 1] in escapes:
            result.extend(escapes[value[index + 1]]); index += 2; continue
        result.extend(value[index].encode("utf-8")); index += 1
    return result.decode("utf-8", errors="replace")

def profile_name(text):
    # ETS2 writes a quoted value for most profiles, but older/current profiles
    # may legally store simple names without quotes.
    match = re.search(r'^\s*profile_name\s*:\s*(?:"(.*)"|(\S.*?))\s*$', text, re.MULTILINE)
    if not match: return None
    return unescape_sii_string(match.group(1) if match.group(1) is not None else match.group(2).strip())

def default_game_path():
    documents = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Documents"
    return str(documents / "Euro Truck Simulator 2")

def same_path(left, right):
    try: return os.path.normcase(os.path.abspath(os.path.expanduser(str(left)))) == os.path.normcase(os.path.abspath(os.path.expanduser(str(right))))
    except (OSError, TypeError, ValueError): return False

def reply(**data):
    # The manager reads stdout as the Windows console code page. Escaping keeps
    # Chinese, Cyrillic and other Unicode mod names from crashing that channel.
    print(json.dumps(data, ensure_ascii=True))

def profiles(game_path):
    root = Path(game_path).expanduser()
    if not root.is_dir(): return None, "game_folder_not_found"
    folder = root / "profiles"
    if not folder.is_dir(): return None, "profiles_folder_not_found"
    found = []
    for item in sorted(folder.iterdir(), key=lambda value: value.name.casefold()):
        profile = item / "profile.sii"
        if not item.is_dir() or not profile.is_file(): continue
        try:
            name = profile_name(profile_text(profile))
            if name is not None: found.append({"directory": item.name, "name": name})
        except (OSError, ValueError, zlib.error):
            continue
    if not found: return None, "no_profiles"
    save_resource_json("profiles.json", {"game_path": str(root), "profiles": found})
    return found, None

def mod_entry(index, value):
    file_name, display_name = (value.split("|", 1) + [value])[:2] if "|" in value else (value, value)
    return {"index": index, "name": unescape_sii_string(display_name), "file": unescape_sii_string(file_name), "sii_value": value}

def active_mod_entries(text):
    values = {}
    for match in re.finditer(r'^\s*active_mods\[(\d+)\]\s*:\s*"(.*)"\s*$', text, re.MULTILINE):
        values[int(match.group(1))] = match.group(2)
    return [mod_entry(index, values[index]) for index in sorted(values, reverse=True)]

def mods(game_path, directory):
    root = Path(game_path).expanduser(); profile = root / "profiles" / directory / "profile.sii"
    if not directory or Path(directory).name != directory or not profile.is_file(): return None, "profile_not_found"
    try: text = profile_text(profile)
    except (OSError, ValueError, zlib.error): return None, "profile_read_failed"
    count = re.search(r'^\s*active_mods\s*:\s*(\d+)\s*$', text, re.MULTILINE)
    active_mods = int(count.group(1)) if count else 0
    # ETS2 treats 0 as the bottom of the stack; present the list from top down.
    return {"active_mods": active_mods, "mods": active_mod_entries(text)}, None

def bundled_presets():
    folder = Path(__file__).resolve().parent / "presets"; presets = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            preset = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(preset, dict) and isinstance(preset.get("mods"), list): presets.append(preset)
        except (OSError, json.JSONDecodeError): pass
    return presets

def local_resource_presets():
    """Read presets created by Preset Creator from every tool resource folder."""
    root = storage_root().parent
    presets = []
    try:
        paths = sorted(root.glob("*/presets/*.json"), key=lambda item: str(item).casefold())
    except OSError:
        paths = []
    for path in paths:
        try:
            preset = json.loads(path.read_text(encoding="utf-8-sig"))
            if isinstance(preset, dict) and isinstance(preset.get("mods"), list):
                presets.append(preset)
        except (OSError, json.JSONDecodeError):
            continue
    return presets

def merge_presets(*groups):
    merged = []
    seen = set()
    for group in groups:
        for preset in group if isinstance(group, list) else []:
            preset_id = str(preset.get("id", "")) if isinstance(preset, dict) else ""
            if not preset_id or preset_id in seen:
                continue
            seen.add(preset_id); merged.append(preset)
    return merged

PRESETS_LIST_URL = "https://lyonzyileonid5.website.yandexcloud.net/tools/verified_tools/a6f3812a4e5b49c695d7f1e8c32b4a0fa6f3812a4e5b49c695d7f1e8c32b4a0f/presets/list.json"

def remote_presets():
    request = Request(PRESETS_LIST_URL, headers={"User-Agent": "SCS-Mega-Manager/1.0"})
    with urlopen(request, timeout=15) as response: listing = response.read().decode("utf-8-sig")
    try:
        parsed = json.loads(listing); entries = parsed.get("list", parsed) if isinstance(parsed, dict) else parsed
        files = [item.get("file") if isinstance(item, dict) else item for item in entries] if isinstance(entries, list) else []
    except json.JSONDecodeError:
        # Accept the initially uploaded compact form: {"list":["file":"name.json"]}.
        files = re.findall(r'"file"\s*:\s*"([^"\\/]+\.json)"', listing)
    presets = []
    for filename in files:
        if not isinstance(filename, str) or Path(filename).name != filename: continue
        with urlopen(Request(urljoin(PRESETS_LIST_URL, filename), headers={"User-Agent": "SCS-Mega-Manager/1.0"}), timeout=20) as response:
            preset = json.loads(response.read().decode("utf-8-sig"))
        if isinstance(preset, dict) and isinstance(preset.get("mods"), list): presets.append(preset)
    return presets

def available_presets(refresh=False):
    # Applying must never wait on the network: use the presets already loaded
    # by the user (and restored at startup). Only the explicit load button
    # refreshes the remote catalogue.
    cached = load_resource_json("presets.json", [])
    local = local_resource_presets()
    if not refresh and isinstance(cached, list) and cached:
        return merge_presets(local, cached)
    try:
        remote = remote_presets()
        if remote:
            save_resource_json("presets.json", remote)
            return merge_presets(local, remote)
    except Exception: pass
    if isinstance(cached, list) and cached: return merge_presets(local, cached)
    return merge_presets(local, bundled_presets())

def preset_mod_value(item):
    if isinstance(item, str) and item: return item
    if isinstance(item, dict) and isinstance(item.get("file"), str) and isinstance(item.get("name"), str): return f"{item['file']}|{item['name']}"
    if isinstance(item, dict) and isinstance(item.get("sii_value"), str) and item["sii_value"]: return item["sii_value"]
    raise ValueError("Invalid preset mod")

def text_save_format_enabled(game_path):
    """ETS2 may safely load an edited plain SII only with save_format set to 2."""
    config = Path(game_path).expanduser() / "config.cfg"
    if not config.is_file(): return False, "config_not_found"
    try:
        content = config.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return False, "config_not_found"
    # The game writes: uset g_save_format "2". Accept the equivalent plain
    # setting too, so an already hand-edited config works as expected.
    allowed = re.search(r'^\s*(?:uset\s+g_)?save_format\s*(?::|\s)\s*"?2"?\s*$', content, re.MULTILINE)
    return (True, None) if allowed else (False, "save_format_must_be_2")

def set_text_save_format(game_path):
    """Set the game option to the editable SII format, preserving config.cfg."""
    config = Path(game_path).expanduser() / "config.cfg"
    if not config.is_file(): return None, "config_not_found"
    try:
        content = config.read_text(encoding="utf-8-sig", errors="replace")
        ending = "\r\n" if "\r\n" in content else "\n"
        setting = re.compile(r'^\s*uset\s+g_save_format\s+(?:"[^"]*"|\S+)\s*$', re.MULTILINE)
        updated, replacements = setting.subn('uset g_save_format "2"', content, count=1)
        if not replacements:
            updated = content.rstrip("\r\n") + ending + 'uset g_save_format "2"' + ending
        backup = storage_root() / f"config.cfg-{datetime.now():%Y%m%d-%H%M%S}.bak"
        shutil.copy2(config, backup)
        handle, temporary = tempfile.mkstemp(prefix="config.cfg.combo-", suffix=".tmp", dir=str(config.parent))
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="") as output: output.write(updated)
            os.replace(temporary, config)
        except Exception:
            try: os.unlink(temporary)
            except OSError: pass
            raise
        return {"backup": str(backup)}, None
    except OSError:
        return None, "config_write_failed"

def profile_path(game_path, directory):
    profile = Path(game_path).expanduser() / "profiles" / directory / "profile.sii"
    return profile if directory and Path(directory).name == directory and profile.is_file() else None

def anchor_index(values, anchor):
    if not isinstance(anchor, dict): return None
    target = str(anchor.get("name", "")).casefold()
    match_kind = str(anchor.get("match", "display_name"))
    if not target: return None
    for index, value in enumerate(values):
        entry = mod_entry(index, value)
        candidate = entry["file"] if match_kind == "file" else entry["name"]
        if candidate.casefold() == target: return index
    return None

def write_mod_values(profile, values, backup_prefix):
    if not all(isinstance(value, str) and value and "\n" not in value and "\r" not in value for value in values): return None, "invalid_mod_order"
    try:
        text = profile_text(profile)
        pattern = re.compile(r'^\s*active_mods\s*:\s*\d+\s*$\n(?:^\s*active_mods\[\d+\]\s*:\s*".*"\s*$\n?)*', re.MULTILINE)
        if not pattern.search(text): return None, "active_mods_not_found"
        ending = "\r\n" if "\r\n" in text else "\n"
        block = f" active_mods: {len(values)}{ending}" + ending.join(f' active_mods[{index}]: "{value}"' for index, value in enumerate(reversed(values))) + ending
        resources = storage_root()
        backup = resources / f"{backup_prefix}-profile.sii-{datetime.now():%Y%m%d-%H%M%S}.bak"
        shutil.copy2(profile, backup)
        handle, temporary = tempfile.mkstemp(prefix="profile.sii.combo-", suffix=".tmp", dir=str(profile.parent))
        try:
            updated = pattern.sub(lambda _match: block, text, count=1).encode("utf-8")
            # save_format 2 is deliberately required above: plain SII is the
            # game-supported, editable format and avoids re-creating ScsC.
            with os.fdopen(handle, "wb") as output: output.write(updated)
            os.replace(temporary, profile)
        except Exception:
            try: os.unlink(temporary)
            except OSError: pass
            raise
        return {"backup": str(backup), "active_mods": len(values), "mods": [mod_entry(len(values) - 1 - index, value) for index, value in enumerate(values)]}, None
    except (OSError, ValueError, zlib.error): return None, "profile_write_failed"

def apply_preset(game_path, directory, preset_id, own_mods=None):
    profile = profile_path(game_path, directory)
    if not profile: return None, "profile_not_found"
    enabled, error = text_save_format_enabled(game_path)
    if not enabled: return None, error
    preset = next((item for item in available_presets() if str(item.get("id")) == str(preset_id)), None)
    if not preset: return None, "preset_not_found"
    try: values = [preset_mod_value(item) for item in preset["mods"]]
    except (KeyError, ValueError): return None, "preset_invalid"
    own_values = [str(value) for value in own_mods] if isinstance(own_mods, list) else []
    own_values = list(dict.fromkeys(value for value in own_values if value not in values))
    if own_values:
        after = anchor_index(values, preset.get("own_mods_after"))
        if after is None: return None, "own_mods_anchor_not_found"
        # The list is displayed from top to bottom: personal mods go above
        # the anchor (for example, Map FIX), leaving the anchor below them.
        values[after:after] = own_values
    result, error = write_mod_values(profile, values, directory)
    if result:
        result["own_mods"] = own_values
        save_resource_json("own_mods.json", {"game_path": str(Path(game_path).expanduser()), "preset_id": str(preset_id), "mods": own_values})
    return result, error

def save_own_mods(game_path, own_mods):
    """Persist the current personal-mod selection before a preset is applied."""
    if not isinstance(own_mods, list): return None, "invalid_mod_order"
    values = []
    for value in own_mods:
        if not isinstance(value, str) or not value or "\n" in value or "\r" in value: return None, "invalid_mod_order"
        if value not in values: values.append(value)
    save_resource_json("own_mods.json", {"game_path": str(Path(game_path).expanduser()), "preset_id": "", "mods": values})
    return {"own_mods": values}, None

def save_mod_order(game_path, directory, values):
    profile = profile_path(game_path, directory)
    if not profile: return None, "profile_not_found"
    enabled, error = text_save_format_enabled(game_path)
    if not enabled: return None, error
    return write_mod_values(profile, values if isinstance(values, list) else [], directory + "-order")

def delete_backups():
    """Remove only backup files created by this tool; settings and presets remain."""
    removed = 0
    try:
        for path in storage_root().glob("*.bak"):
            if path.is_file():
                path.unlink()
                removed += 1
    except OSError:
        return None, "backup_delete_failed"
    return {"removed": removed}, None

def backup_entries():
    entries = []
    for path in sorted(storage_root().glob("*.bak"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            created = datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
            if path.name.startswith("config.cfg-"):
                entries.append({"id": path.name, "name": path.name, "kind": "config", "created": created, "mods": [], "mod_count": 0})
                continue
            match = re.match(r"^(.+)-profile\.sii-\d{8}-\d{6}\.bak$", path.name)
            if not match: continue
            directory = match.group(1).removesuffix("-order")
            text = profile_text(path); mods_list = active_mod_entries(text)
            entries.append({"id": path.name, "name": path.name, "kind": "profile", "profile_dir": directory, "created": created, "mods": mods_list, "mod_count": len(mods_list)})
        except (OSError, ValueError, zlib.error):
            continue
    return entries, None

def restore_backup(game_path, backup_id):
    if not isinstance(backup_id, str) or Path(backup_id).name != backup_id or not backup_id.endswith(".bak"): return None, "backup_not_found"
    source = storage_root() / backup_id
    if not source.is_file(): return None, "backup_not_found"
    if backup_id.startswith("config.cfg-"):
        target = Path(game_path).expanduser() / "config.cfg"
    else:
        match = re.match(r"^(.+)-profile\.sii-\d{8}-\d{6}\.bak$", backup_id)
        if not match: return None, "backup_not_found"
        target = Path(game_path).expanduser() / "profiles" / match.group(1).removesuffix("-order") / "profile.sii"
    if not target.is_file(): return None, "restore_target_not_found"
    try:
        safety = storage_root() / f"restore-before-{target.name}-{datetime.now():%Y%m%d-%H%M%S}.bak"
        shutil.copy2(target, safety); shutil.copy2(source, target)
        return {"backup": backup_id, "safety_backup": str(safety)}, None
    except OSError: return None, "restore_failed"

def verification_preset(preset_id):
    preset = next((item for item in available_presets() if str(item.get("id")) == str(preset_id)), None)
    return preset if isinstance(preset, dict) else None

def active_log_mods(game_path):
    log = Path(game_path).expanduser() / "game.log.txt"
    if not log.is_file(): return None, "game_log_not_found"
    try: lines = log.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError: return None, "game_log_not_found"
    # The active-mod list is emitted during game start, not at the end of a
    # complete game.log.txt. Looking backwards from EOF would lose the list
    # after the player continues past loading.
    headers = [index for index, line in enumerate(lines) if re.search(r"\[mods\]\s+Active\s+\d+\s+mods\s*\(", line)]
    if not headers: return None, "active_mods_log_not_found"
    start = headers[-1] + 1
    local_pattern = re.compile(r"\[mods\]\s+Active local mod\s+(.*?)\s+\(name:\s*(.*?),\s*version:\s*(.*?),\s*author:\s*(.*)\)\s*$")
    workshop_pattern = re.compile(r"\[mods\]\s+Active workshop mod ID\s+(\d+)\s+\(name:\s*(.*?),\s*version:\s*(.*?),\s*author:\s*(.*)\)\s*$")
    mods = {}
    reading_block = False
    for line in lines[start:]:
        match = local_pattern.search(line)
        if match:
            file_id, name, version, author = match.groups()
            mods[file_id] = {"log_name": name, "version": version, "author": author}
            reading_block = True
            continue
        match = workshop_pattern.search(line)
        if match:
            workshop_id, name, version, author = match.groups()
            mods[f"workshop:{workshop_id}"] = {"log_name": name, "version": version, "author": author}
            reading_block = True
            continue
        # A later game session may be present in the same file. Active-mod
        # records belong to one uninterrupted startup block only.
        if reading_block: break
    return mods, None

def prepared_log(game_path, preset_id):
    cached = load_resource_json("verification_log.json", {})
    if isinstance(cached, dict) and cached.get("game_path") == str(Path(game_path).expanduser()) and cached.get("preset_id") == str(preset_id) and isinstance(cached.get("mods"), dict): return cached["mods"], None
    return None, "verification_not_prepared"

def mod_archive(game_path, file_id):
    folder = Path(game_path).expanduser() / "mod"
    for suffix in (".scs", ".zip"):
        candidate = folder / f"{file_id}{suffix}"
        if candidate.is_file(): return candidate
    return None

def prepare_verification(game_path, preset_id):
    if not verification_preset(preset_id): return None, "preset_not_found"
    mods, error = active_log_mods(game_path)
    if error: return None, error
    save_resource_json("verification_log.json", {"game_path": str(Path(game_path).expanduser()), "preset_id": str(preset_id), "mods": mods})
    return {"active_mods": len(mods)}, None

def verify_mod_files(game_path, preset_id):
    preset = verification_preset(preset_id)
    if not preset: return None, "preset_not_found"
    missing = []
    for item in preset.get("mods", []):
        if not isinstance(item, dict) or not isinstance(item.get("file"), str): continue
        if not isinstance(item.get("verification"), dict): continue
        file_id = unescape_sii_string(item["file"])
        if not mod_archive(game_path, file_id): missing.append({"file": file_id, "name": unescape_sii_string(str(item.get("name", file_id)))})
    return {"missing": missing, "checked": len(preset.get("mods", []))}, None

def verify_mod_parameters(game_path, preset_id):
    preset = verification_preset(preset_id)
    if not preset: return None, "preset_not_found"
    logged, error = prepared_log(game_path, preset_id)
    if error: return None, error
    mismatches = []
    for item in preset.get("mods", []):
        if not isinstance(item, dict) or not isinstance(item.get("file"), str): continue
        if not isinstance(item.get("verification"), dict): continue
        expected = item["verification"]
        file_id = unescape_sii_string(item["file"]); actual = logged.get(file_id); problems = []
        for key in ("log_name", "version", "author"):
            if key in expected and (not actual or str(actual.get(key, "")) != str(expected[key])): problems.append(key)
        if "size" in expected:
            archive = mod_archive(game_path, file_id)
            if not archive or archive.stat().st_size != int(expected["size"]): problems.append("size")
        if problems: mismatches.append({"file": file_id, "name": unescape_sii_string(str(item.get("name", file_id))), "problems": problems})
    return {"mismatches": mismatches, "checked": len(preset.get("mods", []))}, None

def verify_preset(game_path, preset_id, own_mods=None):
    """Run the complete check in one request and retain the parsed log for display."""
    preset = verification_preset(preset_id)
    if not preset: return None, "preset_not_found"
    prepared, error = prepare_verification(game_path, preset_id)
    if error: return None, error
    files, error = verify_mod_files(game_path, preset_id)
    if error: return None, error
    parameters, error = verify_mod_parameters(game_path, preset_id)
    if error: return None, error
    logged, error = prepared_log(game_path, preset_id)
    if error: return None, error
    log_mods = [{"file": file_id, **value} for file_id, value in logged.items()]
    expected_files = {unescape_sii_string(item["file"]) for item in preset.get("mods", []) if isinstance(item, dict) and isinstance(item.get("file"), str)}
    if not isinstance(own_mods, list):
        saved = load_resource_json("own_mods.json", {})
        own_mods = saved.get("mods", []) if isinstance(saved, dict) and saved.get("game_path") == str(Path(game_path).expanduser()) and saved.get("preset_id") == str(preset_id) else []
    own_files = set()
    for value in own_mods:
        if not isinstance(value, str): continue
        file_id = unescape_sii_string(value.split("|", 1)[0])
        workshop = re.fullmatch(r"workshop[.:](\d+)", file_id, re.I)
        package = re.fullmatch(r"mod_workshop_package\.([0-9a-f]+)", file_id, re.I)
        if workshop: own_files.add(f"workshop:{workshop.group(1)}")
        elif package: own_files.add(f"workshop:{int(package.group(1), 16)}")
        else: own_files.add(file_id)
    extra_mods = [{"file": file_id, "name": value.get("log_name", file_id)} for file_id, value in logged.items() if file_id not in expected_files and file_id not in own_files]
    # A missing archive cannot also be a meaningful log mismatch. Present it
    # once in the more actionable "missing" section.
    missing_files = {item.get("file") for item in files["missing"] if isinstance(item, dict)}
    mismatches = [item for item in parameters["mismatches"] if item.get("file") not in missing_files]
    return {"active_mods": log_mods, "missing": files["missing"], "mismatches": mismatches, "extra_mods": extra_mods}, None

def main():
    try: data = json.loads(os.environ.get("SCS_TOOL_INPUT", "{}"))
    except json.JSONDecodeError: return reply(status="error", code="generic")
    action = data.get("action")
    if action == "defaults":
        settings = load_resource_json("settings.json", {})
        game_path = settings.get("game_path") or default_game_path()
        # Refresh the game's save/profile list once when the tool opens.  All
        # later actions use the already displayed selection; no save data is
        # re-read in the background while the user works.
        refreshed, _error = profiles(game_path)
        profile_cache = load_resource_json("profiles.json", {})
        cached_profiles = refreshed if refreshed else (profile_cache.get("profiles", []) if isinstance(profile_cache, dict) and same_path(profile_cache.get("game_path"), game_path) else [])
        cached_presets = load_resource_json("presets.json", [])
        saved_own_mods = load_resource_json("own_mods.json", {})
        own_mods = saved_own_mods.get("mods", []) if isinstance(saved_own_mods, dict) and same_path(saved_own_mods.get("game_path"), game_path) and isinstance(saved_own_mods.get("mods"), list) else []
        return reply(status="defaults", game_path=game_path, profiles=cached_profiles if isinstance(cached_profiles, list) else [], presets=cached_presets if isinstance(cached_presets, list) else [], own_mods=own_mods)
    game_path = str(data.get("game_path", "")).strip()
    if action == "scan_profiles":
        value, error = profiles(game_path)
        if not error: save_resource_json("settings.json", {"game_path": game_path})
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, profiles=value)
    if action == "read_mods":
        value, error = mods(game_path, str(data.get("profile_dir", "")))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "load_presets":
        presets = available_presets(refresh=True)
        save_resource_json("presets.json", presets)
        return reply(status="ok", action=action, presets=[{"id": item.get("id"), "name": item.get("name") or item.get("id"), "blocked_mod_keywords": item.get("blocked_mod_keywords", [])} for item in presets])
    if action == "apply_preset":
        value, error = apply_preset(game_path, str(data.get("profile_dir", "")), data.get("preset_id"), data.get("own_mods"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "save_own_mods":
        value, error = save_own_mods(game_path, data.get("own_mods"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "save_mod_order":
        value, error = save_mod_order(game_path, str(data.get("profile_dir", "")), data.get("mods"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "delete_backups":
        value, error = delete_backups()
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "list_backups":
        value, error = backup_entries()
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, backups=value)
    if action == "restore_backup":
        value, error = restore_backup(game_path, data.get("backup_id"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "prepare_verification":
        value, error = prepare_verification(game_path, data.get("preset_id"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "verify_mod_files":
        value, error = verify_mod_files(game_path, data.get("preset_id"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "verify_mod_parameters":
        value, error = verify_mod_parameters(game_path, data.get("preset_id"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "verify_preset":
        value, error = verify_preset(game_path, data.get("preset_id"), data.get("own_mods"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "set_save_format":
        value, error = set_text_save_format(game_path)
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    reply(status="error", action=action, code="generic")


import hashlib
import base64
import html as html_lib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import mmap
import struct
import threading
from urllib.parse import unquote, urlparse

# Profile Mod Manager owns the profile's load order.  Saving uses the shared
# safe writer from Combo Installer, which creates a backup before replacement.
SCS_ACTIONS = ("defaults", "scan_profiles", "read_mods", "load_mod_metadata", "save_mod_order", "load_mod_groups", "save_mod_groups", "load_mod_view_settings", "save_mod_view_settings", "export_mod_report", "import_html_preset", "list_order_presets", "save_order_preset", "delete_order_preset", "autosave_order", "clear_order_autosaves", "list_order_history", "undo_order_history", "redo_order_history")
SCS_OUTPUT_IDS = ("status", "result")

class CentralDirectoryZip:
    """Read SCS-compatible ZIP files from their central directory.

    Some protected SCS mods deliberately put false flags, names and compression
    details in local headers.  Like the supplied ZipReader.cs, this reader uses
    only the local name/extra lengths to locate payload data and takes all
    meaningful metadata from the central directory.
    """
    def __init__(self, path):
        self._file = open(path, "rb")
        self.data = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        self.is_aem = self.data[:4] == b"AEM!"
        self.entries = {}
        self._read_directory()

    def _read_directory(self):
        data = self.data
        start = max(0, len(data) - (22 + 0xffff))
        eocd = -1
        for offset in range(len(data) - 22, start - 1, -1):
            if data[offset:offset + 4] != b"PK\x05\x06":
                continue
            comment = self._u16(offset + 20)
            record_end = offset + 22 + comment
            if record_end == len(data) or (self.is_aem and record_end <= len(data)):
                eocd = offset
                break
        if eocd < 0:
            raise ValueError("not_a_zip_archive")
        count, directory_size, directory_offset = self._u16(eocd + 10), self._u32(eocd + 12), self._u32(eocd + 16)
        if count == 0xffff or directory_size == 0xffffffff or directory_offset == 0xffffffff:
            locator = eocd - 20
            if locator < 0 or data[locator:locator + 4] != b"PK\x06\x07":
                raise ValueError("zip64_locator_missing")
            zip64 = self._u64(locator + 8)
            if data[zip64:zip64 + 4] != b"PK\x06\x06":
                raise ValueError("zip64_record_missing")
            count, directory_size, directory_offset = self._u64(zip64 + 32), self._u64(zip64 + 40), self._u64(zip64 + 48)
        if directory_offset < 0 or directory_offset > len(data):
            raise ValueError("invalid_central_directory")
        offset = directory_offset
        for _ in range(count):
            if data[offset:offset + 4] != b"PK\x01\x02":
                raise ValueError("invalid_central_entry")
            flags, method = self._u16(offset + 8), self._u16(offset + 10)
            compressed, uncompressed = self._u32(offset + 20), self._u32(offset + 24)
            name_length, extra_length, comment_length = self._u16(offset + 28), self._u16(offset + 30), self._u16(offset + 32)
            local_offset = self._u32(offset + 42)
            name_start = offset + 46
            name_raw = data[name_start:name_start + name_length]
            encoding = "utf-8" if flags & 0x800 else "cp437"
            name = name_raw.decode(encoding, errors="replace").replace("\\", "/").lstrip("/")
            extra = data[name_start + name_length:name_start + name_length + extra_length]
            compressed, uncompressed, local_offset = self._zip64_values(extra, compressed, uncompressed, local_offset)
            self.entries[name.casefold()] = (name, method, compressed, uncompressed, local_offset)
            offset = name_start + name_length + extra_length + comment_length

    @staticmethod
    def _zip64_values(extra, compressed, uncompressed, local_offset):
        wanted = (uncompressed == 0xffffffff, compressed == 0xffffffff, local_offset == 0xffffffff)
        if not any(wanted):
            return compressed, uncompressed, local_offset
        cursor = 0
        while cursor + 4 <= len(extra):
            tag, length = struct.unpack_from("<HH", extra, cursor); value = cursor + 4; end = value + length
            if end > len(extra): break
            if tag == 1:
                if wanted[0]: uncompressed = struct.unpack_from("<Q", extra, value)[0]; value += 8
                if wanted[1]: compressed = struct.unpack_from("<Q", extra, value)[0]; value += 8
                if wanted[2]: local_offset = struct.unpack_from("<Q", extra, value)[0]
                return compressed, uncompressed, local_offset
            cursor = end
        raise ValueError("zip64_extra_missing")

    def _u16(self, offset): return struct.unpack_from("<H", self.data, offset)[0]
    def _u32(self, offset): return struct.unpack_from("<I", self.data, offset)[0]
    def _u64(self, offset): return struct.unpack_from("<Q", self.data, offset)[0]

    def read(self, requested):
        key = str(requested).replace("\\", "/").lstrip("/").casefold()
        entry = self.entries.get(key)
        if not entry: return None
        _name, method, compressed, uncompressed, local = entry
        if self.data[local:local + 4] not in (b"PK\x03\x04", b"AEM!"):
            raise ValueError("invalid_local_header")
        name_length, extra_length = self._u16(local + 26), self._u16(local + 28)
        payload = self.data[local + 30 + name_length + extra_length:local + 30 + name_length + extra_length + compressed]
        if len(payload) != compressed: raise ValueError("truncated_archive_entry")
        if method == 0: output = payload
        elif method == 8: output = zlib.decompress(payload, -zlib.MAX_WBITS)
        else: raise ValueError("unsupported_zip_compression")
        if len(output) != uncompressed: raise ValueError("invalid_archive_entry_size")
        return output

MASK64 = (1 << 64) - 1
K0, K1, K2, K3, KMUL = 0xc3a5c85c97cb3127, 0xb492b66fbe98f273, 0x9ae16a3b2f90404f, 0xc949d7c7509e6557, 0x9ddfea08eb382d69
def _u64(value): return value & MASK64
def _rot(value, shift): return ((value >> shift) | (value << (64 - shift))) & MASK64 if shift else value
def _f64(data, offset): return struct.unpack_from("<Q", data, offset)[0]
def _f32(data, offset): return struct.unpack_from("<I", data, offset)[0]
def _mix(value):
    value &= MASK64
    return value ^ (value >> 47)
def _h16(low, high):
    a = _u64((low ^ high) * KMUL); a ^= a >> 47
    b = _u64((high ^ a) * KMUL); b ^= b >> 47
    return _u64(b * KMUL)
def cityhash64(data):
    """The original CityHash variant used by SCS HashFS, for asset paths."""
    length = len(data)
    if length <= 16:
        if length > 8:
            a, b = _f64(data, 0), _f64(data, length - 8)
            return _h16(a, _rot(_u64(b + length), length)) ^ b
        if length >= 4: return _h16(length + (_f32(data, 0) << 3), _f32(data, length - 4))
        if length:
            a, b, c = data[0], data[length >> 1], data[-1]
            return _u64(_mix(_u64((a + (b << 8)) * K2) ^ _u64((length + (c << 2)) * K3)) * K2)
        return K2
    if length <= 32:
        a, b = _u64(_f64(data, 0) * K1), _f64(data, 8)
        c, d = _u64(_f64(data, length - 8) * K2), _u64(_f64(data, length - 16) * K0)
        return _h16(_u64(_rot(_u64(a - b), 43) + _rot(c, 30) + d), _u64(a + _rot(b ^ K3, 20) - c + length))
    if length <= 64:
        z = _f64(data, 24); a = _u64(_f64(data, 0) + _u64((length + _f64(data, length - 16)) * K0)); b = _rot(_u64(a + z), 52); c = _rot(a, 37)
        a = _u64(a + _f64(data, 8)); c = _u64(c + _rot(a, 7)); a = _u64(a + _f64(data, 16)); vf, vs = _u64(a + z), _u64(b + _rot(a, 31) + c)
        a = _u64(_f64(data, 16) + _f64(data, length - 32)); z = _f64(data, length - 8); b = _rot(_u64(a + z), 52); c = _rot(a, 37)
        a = _u64(a + _f64(data, length - 24)); c = _u64(c + _rot(a, 7)); a = _u64(a + _f64(data, length - 16)); wf, ws = _u64(a + z), _u64(b + _rot(a, 31) + c)
        return _u64(_mix(_u64(_mix(_u64(vf + ws) * K2 + _u64(wf + vs) * K0) * K0 + vs)) * K2)
    # Mod manifests and their icon paths are short; long paths cannot be direct
    # manifest/icon candidates and are intentionally not traversed here.
    raise ValueError("hashfs_path_too_long")

class HashFsArchive:
    """Minimal HashFS v1/v2 reader for direct manifest and icon lookups."""
    def __init__(self, path):
        self._file = open(path, "rb")
        self.data = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        if self.data[:4] != b"SCS#" or self.data[8:12] != b"CITY": raise ValueError("not_hashfs")
        self.version = struct.unpack_from("<H", self.data, 4)[0]
        # Header bytes 6-7 store the v1 path-hash salt. Most archives use
        # zero, but protected archives can use a decimal prefix such as 2375.
        self.salt = struct.unpack_from("<H", self.data, 6)[0]
        self.entries = {}
        if self.version == 1: self._v1()
        elif self.version == 2: self._v2()
        else: raise ValueError("unsupported_hashfs_version")
    def _v1(self):
        count, table = struct.unpack_from("<II", self.data, 12)
        for index in range(count):
            value = struct.unpack_from("<QQIIII", self.data, table + index * 32)
            self.entries[value[0]] = (value[1], value[5], value[4], 0x10 if value[2] & 2 else 0)
    def _v2(self):
        count, et_size, words, mt_size, et_off, mt_off = struct.unpack_from("<IIIIQQ", self.data, 12)
        et = zlib.decompress(self.data[et_off:et_off + et_size]); mt = zlib.decompress(self.data[mt_off:mt_off + mt_size])
        if len(et) != count * 16 or len(mt) != words * 4: raise ValueError("invalid_hashfs_index")
        for index in range(count):
            hashed, meta_index, parts, flags = struct.unpack_from("<QIHH", et, index * 16)
            for part in range(parts):
                at = (meta_index + part) * 4; low, high, kind = struct.unpack_from("<HBB", mt, at); head = (low | high << 16) * 4
                if kind & 0x80:
                    zs_low, zs_high, flags2, us_low, us_high, _flags3, _unknown, block = struct.unpack_from("<HBBHBBII", mt, head)
                    self.entries[hashed] = (block * 16, zs_low | zs_high << 16, us_low | us_high << 16, flags2 & 0xf0)
                    break
    def read(self, requested):
        path = str(requested).replace("\\", "/").lstrip("/")
        # HashFS v1 prepends the *decimal* salt to a path before CityHash.
        # Keep v2 unchanged: its salt handling is not compatible with v1.
        hashed_path = f"{self.salt}{path}" if self.version == 1 and self.salt else path
        entry = self.entries.get(cityhash64(hashed_path.encode("utf-8")))
        if not entry: return None
        offset, packed, size, compression = entry; raw = self.data[offset:offset + packed]
        value = raw if compression == 0 else zlib.decompress(raw) if compression == 0x10 else None
        if value is None or len(value) != size: return None
        return value

def archive_entry(path, requested):
    """Return an entry from native SCS HashFS or SCS-compatible ZIP."""
    try:
        if Path(path).is_dir():
            entry = Path(path) / Path(str(requested).replace("\\", "/").lstrip("/"))
            return entry.read_bytes() if entry.is_file() else None
        with open(path, "rb") as source: raw = source.read(3)
        return HashFsArchive(path).read(requested) if raw == b"SCS" else CentralDirectoryZip(path).read(requested)
    except (OSError, ValueError, struct.error, zlib.error):
        return None

def sii_values(content, key):
    # Manifests commonly leave an explanatory ``# comment`` after a value.
    # It is not part of the SII value and must not make the whole field fail.
    expression = rf'^\s*{re.escape(key)}(?:\[\])?\s*:\s*(?:"((?:\\.|[^"\\])*)"|([^\s#]+))(?:\s*(?://|#).*)?\s*$'
    found = []
    for match in re.finditer(expression, content, re.MULTILINE | re.IGNORECASE):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        found.append(unescape_sii_string(value.strip()))
    return found

ICON_WRITE_LOCK = threading.Lock()

def image_data_uri(data, name):
    """Cache an archive icon as a local file usable by QtWebEngine.

    QtWebEngine reports WebP ``data:`` URLs as loaded but, in some builds,
    fails to composite them inside dynamically replaced cards.  A local URL is
    reliable and keeps huge base64 payloads out of bridge responses and JSON.
    """
    if not data or len(data) > 1024 * 1024: return ""
    suffix = Path(name).suffix.casefold()
    mime = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif", ".bmp": "image/bmp"}.get(suffix)
    if not mime:
        if data.startswith(b"\x89PNG"): mime = "image/png"
        elif data.startswith(b"\xff\xd8\xff"): mime = "image/jpeg"
        elif data.startswith(b"RIFF") and data[8:12] == b"WEBP": mime = "image/webp"
        elif data.startswith((b"GIF87a", b"GIF89a")): mime = "image/gif"
    if not mime: return ""
    extension = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "image/gif": ".gif", "image/bmp": ".bmp"}[mime]
    try:
        directory = storage_root() / "mod_icons"; directory.mkdir(parents=True, exist_ok=True)
        target = directory / (hashlib.sha256(data).hexdigest() + extension)
        with ICON_WRITE_LOCK:
            if not target.is_file() or target.stat().st_size != len(data): target.write_bytes(data)
        return target.resolve().as_uri()
    except OSError:
        return ""

def description_text(data):
    """Decode the game description file without treating its colour tags as SII."""
    if not data: return ""
    for encoding in ("utf-8-sig", "utf-8", "cp1251"):
        try: return data.decode(encoding).replace("\x00", "").strip()
        except UnicodeDecodeError: continue
    return data.decode("latin-1", errors="replace").replace("\x00", "").strip()

def manifest_metadata(path):
    manifest = archive_entry(path, "manifest.sii")
    if not manifest: return {}
    try: content = decode_sii(manifest)
    except (ValueError, UnicodeDecodeError, zlib.error): content = manifest.decode("utf-8", errors="replace")
    version = sii_values(content, "package_version")
    name = sii_values(content, "display_name")
    author = sii_values(content, "author")
    optional = sii_values(content, "mp_mod_optional")
    icon_name = (sii_values(content, "icon") or [""])[0]
    description_name = (sii_values(content, "description_file") or [""])[0]
    icon = image_data_uri(archive_entry(path, icon_name), icon_name) if icon_name else ""
    return {
        "name": name[0] if name else "", "version": version[0] if version else "",
        "author": author[0] if author else "", "convoy": optional[0].casefold() == "true" if optional else None,
        "dlc": sii_values(content, "dlc_dependencies"),
        "compatible_versions": sii_values(content, "compatible_versions"),
        "categories": sii_values(content, "category"), "icon": icon,
        "description": description_text(archive_entry(path, description_name)) if description_name else "",
    }

def cached_icon_available(value):
    """A cached icon is valid only while its local resource file exists."""
    if not isinstance(value, str) or not value.startswith("file:"):
        return False
    try:
        local_path = unquote(urlparse(value).path)
        if re.match(r"^/[A-Za-z]:/", local_path): local_path = local_path[1:]
        return Path(local_path).is_file()
    except (OSError, ValueError):
        return False

def mod_metadata_cache(folder, names, retry_icons=False, verify_cache=False):
    """Read mod manifests concurrently and retain results until a file changes."""
    raw_cache = load_resource_json("mod_manifest_cache.json", {})
    cache = raw_cache if isinstance(raw_cache, dict) else {}
    result, pending, next_cache, cache_changed = {}, [], dict(cache), False
    for name in names:
        path = folder / name
        try:
            stat = path.stat(); fingerprint = f"{stat.st_size}:{stat.st_mtime_ns}"
        except OSError:
            continue
        key = str(path.resolve()).casefold(); record = cache.get(key)
        metadata = record.get("metadata") if isinstance(record, dict) else None
        icon_file_missing = isinstance(metadata, dict) and bool(metadata.get("icon")) and not cached_icon_available(metadata.get("icon"))
        retry_needed = retry_icons and isinstance(metadata, dict) and not metadata.get("icon")
        # An empty mapping means that an earlier parser could not inspect the
        # archive.  Do not preserve that failure forever: retry it on the next
        # metadata request, while still reusing every real manifest instantly.
        if isinstance(record, dict) and record.get("fingerprint") == fingerprint and isinstance(metadata, dict) and metadata and not retry_needed and not icon_file_missing and not verify_cache:
            result[name.casefold()] = record["metadata"]; next_cache[key] = record
        else:
            pending.append((name, path, key, fingerprint))
    # Archive reads are I/O-bound. A bounded worker pool is substantially faster
    # for a large mod folder without exhausting file handles or RAM.
    with ThreadPoolExecutor(max_workers=min(16, max(6, (os.cpu_count() or 4) * 2))) as pool:
        futures = {pool.submit(manifest_metadata, path): (name, key, fingerprint) for name, path, key, fingerprint in pending}
        for future in as_completed(futures):
            name, key, fingerprint = futures[future]
            try: metadata = future.result()
            except Exception: metadata = {}
            result[name.casefold()] = metadata
            replacement = {"fingerprint": fingerprint, "metadata": metadata}
            if next_cache.get(key) != replacement:
                next_cache[key] = replacement; cache_changed = True
    # A full verification can involve hundreds of responses. Persist only
    # changed records, otherwise repeatedly writing embedded icon data would
    # be needlessly expensive.
    if cache_changed: save_resource_json("mod_manifest_cache.json", next_cache)
    return result

def cached_mod_metadata(folder, names):
    """Return only still-valid cache records, without opening any archives."""
    raw_cache = load_resource_json("mod_manifest_cache.json", {})
    cache = raw_cache if isinstance(raw_cache, dict) else {}
    result = {}
    for name in names:
        path = folder / name
        try:
            stat = path.stat(); fingerprint = f"{stat.st_size}:{stat.st_mtime_ns}"
        except OSError:
            continue
        record = cache.get(str(path.resolve()).casefold())
        metadata = record.get("metadata") if isinstance(record, dict) else None
        icon_file_missing = isinstance(metadata, dict) and bool(metadata.get("icon")) and not cached_icon_available(metadata.get("icon"))
        # Empty cached metadata is deliberately omitted so the front end adds
        # that archive to its background parsing queue again.
        if isinstance(metadata, dict) and metadata and record.get("fingerprint") == fingerprint and not icon_file_missing:
            result[name.casefold()] = metadata
    return result

def mod_folder_names(root):
    folder = Path(root).expanduser() / "mod"
    if not folder.is_dir(): return []
    try:
        return sorted((item.name for item in folder.iterdir()
                       if item.is_dir() or (item.is_file() and item.suffix.casefold() in (".scs", ".zip"))), key=str.casefold)
    except OSError: return []

ARCHIVE_SUFFIXES = {".scs", ".zip", ".7z", ".rar"}

def mod_file_aliases(value):
    """Return a name and all archive-suffix-free forms of it.

    ``map.scs.zip`` is valid in a mod folder; a profile can refer to it as
    ``map``, ``map.scs`` or its full filename.  Dotted version numbers must
    remain intact, so only known archive suffixes are removed.
    """
    current = Path(str(value).replace("\\", "/")).name
    aliases = [current]
    while Path(current).suffix.casefold() in ARCHIVE_SUFFIXES:
        next_name = Path(current).stem
        if next_name == current: break
        aliases.append(next_name); current = next_name
    return aliases

def mod_folder_index(root):
    """Index mod files once; large mod folders must not be scanned per mod."""
    names = mod_folder_names(root)
    exact = {name.casefold(): name for name in names}
    stems = {}
    for name in names:
        for alias in mod_file_aliases(name)[1:]:
            stems.setdefault(alias.casefold(), []).append(name)
    return names, exact, stems

def mod_file_details(folder, names):
    """Lightweight filesystem metadata used for local-library sorting."""
    result = {}
    for name in names:
        try:
            stat = (folder / name).stat()
            result[name.casefold()] = {"created": stat.st_ctime, "size": stat.st_size}
        except OSError:
            result[name.casefold()] = {"created": 0, "size": 0}
    return result

def resolved_mod_file(sii_file, index):
    """Prefer the real extension in mod/, otherwise show the SII file stem."""
    original = unescape_sii_string(sii_file)
    safe = Path(original.replace("\\", "/")).name
    if not safe: return original
    _names, exact, stems = index
    if safe.casefold() in exact: return exact[safe.casefold()]
    # A dot is valid in a version number (for example "My Mod 1.2").  Match
    # every progressively archive-suffix-free form, including .scs.zip.
    for alias in mod_file_aliases(safe):
        matches = stems.get(alias.casefold(), [])
        if matches:
            # .scs is the standard local-mod archive and wins when several
            # forms of the same mod exist in the folder.
            return next((name for name in matches if Path(name).suffix.casefold() == ".scs"), matches[0])
    return safe

def manager_mod_entries(root, text, metadata):
    values = {}
    for match in re.finditer(r'^\s*active_mods\[(\d+)\]\s*:\s*"(.*)"\s*$', text, re.MULTILINE):
        values[int(match.group(1))] = match.group(2)
    entries = []; folder_index = mod_folder_index(root)
    for index in sorted(values, reverse=True):
        value = values[index]
        file_value, name_value = (value.split("|", 1) + [value])[:2] if "|" in value else (value, value)
        info = metadata.get(file_value.casefold()) or metadata.get(resolved_mod_file(file_value, folder_index).casefold(), {})
        entries.append({
            "index": index,
            "file": resolved_mod_file(file_value, folder_index),
            "name": unescape_sii_string(name_value),
            "name": info.get("name") or unescape_sii_string(name_value),
            "version": info.get("version", ""), "author": info.get("author", ""),
            "convoy": info.get("convoy"), "dlc": info.get("dlc", []),
            "compatible_versions": info.get("compatible_versions", []),
            "categories": info.get("categories", []), "icon": info.get("icon", ""),
            "sii_value": value,
        })
    return entries

def game_log_info(root):
    """Read the currently loaded game version and DLC packages from game.log."""
    log_path = Path(root).expanduser() / "game.log.txt"
    try: content = log_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError: return {"game_log_found": False, "game_version": "", "game_dlcs": []}
    version = re.search(r"\[ufs\]\s+Loaded pack set version\s+([0-9]+(?:\.[0-9]+)+)", content, re.IGNORECASE)
    dlcs = sorted({match.group(1).casefold() for match in re.finditer(r"\[(?:hashfs|zipfs)\]\s+(dlc_[a-z0-9_]+)\.scs:\s+Created(?:\s+and\s+validated)?", content, re.IGNORECASE)})
    return {"game_log_found": True, "game_version": version.group(1) if version else "", "game_dlcs": dlcs}

def manager_mods(game_path, directory):
    root = Path(game_path).expanduser(); profile = root / "profiles" / directory / "profile.sii"
    if not directory or Path(directory).name != directory or not profile.is_file(): return None, "profile_not_found"
    try: text = profile_text(profile)
    except (OSError, ValueError, zlib.error): return None, "profile_read_failed"
    count = re.search(r'^\s*active_mods\s*:\s*(\d+)\s*$', text, re.MULTILINE)
    folder_names, _exact, _stems = mod_folder_index(root)
    folder = root / "mod"
    # Render both lists first. Archive work is then requested in small batches
    # so a large mod folder never blocks the initial UI response.
    # Reuse cache immediately. Only unknown or changed archives are then
    # requested by the browser in batches.
    metadata = cached_mod_metadata(folder, folder_names)
    entries = manager_mod_entries(root, text, metadata)
    # profile.sii is the authoritative source for the in-game title of an
    # active mod.  Reuse it in the general mod library immediately, before
    # background manifest loading begins.
    profile_names = {entry["file"].casefold(): entry["name"] for entry in entries if entry.get("name")}
    details = mod_file_details(folder, folder_names)
    for entry in entries:
        entry.update(details.get(entry["file"].casefold(), {"created": 0, "size": 0}))
    folder_mods = [{
        "file": name,
        "name": metadata.get(name.casefold(), {}).get("name") or profile_names.get(name.casefold(), "") or Path(name).stem,
        "version": metadata.get(name.casefold(), {}).get("version", ""),
        "author": metadata.get(name.casefold(), {}).get("author", ""),
        "convoy": metadata.get(name.casefold(), {}).get("convoy"),
        "dlc": metadata.get(name.casefold(), {}).get("dlc", []),
        "compatible_versions": metadata.get(name.casefold(), {}).get("compatible_versions", []),
        "categories": metadata.get(name.casefold(), {}).get("categories", []),
        "icon": metadata.get(name.casefold(), {}).get("icon", ""),
        "description": metadata.get(name.casefold(), {}).get("description", ""),
        "metadata_loaded": name.casefold() in metadata,
        "manifest_found": bool(metadata.get(name.casefold(), {})),
        **details.get(name.casefold(), {"created": 0, "size": 0}),
    } for name in folder_names]
    return {"active_mods": int(count.group(1)) if count else 0, "mods": entries, "folder_mods": folder_mods, **game_log_info(root)}, None

def load_mod_metadata(game_path, requested_names, retry_icons=False, verify_cache=False):
    root = Path(game_path).expanduser(); folder = root / "mod"
    if not folder.is_dir(): return [], None
    available = {item.name.casefold(): item.name for item in folder.iterdir()
                 if item.is_dir() or (item.is_file() and item.suffix.casefold() in (".scs", ".zip"))}
    names = []
    for value in requested_names if isinstance(requested_names, list) else []:
        if not isinstance(value, str): continue
        name = available.get(Path(value).name.casefold())
        if name: names.append(name)
    metadata = mod_metadata_cache(folder, names, bool(retry_icons), bool(verify_cache))
    return [{"file": name, "metadata_loaded": True, "manifest_found": bool(metadata.get(name.casefold(), {})), **metadata.get(name.casefold(), {})} for name in names], None

def sii_escape_string(value):
    """Encode text safely for a quoted plain-SII value.

    ETS2 profiles commonly represent non-ASCII filename bytes as ``\\xNN``.
    Writing literal Unicode can work in a text editor but is not reliably read
    by the game, especially for Central-European mod names.
    """
    escaped = []
    for byte in str(value).encode("utf-8"):
        if byte == 0x5c: escaped.append("\\\\")
        elif byte == 0x22: escaped.append('\\"')
        elif byte == 0x0a: escaped.append("\\n")
        elif byte == 0x0d: escaped.append("\\r")
        elif byte == 0x09: escaped.append("\\t")
        elif 0x20 <= byte <= 0x7e: escaped.append(chr(byte))
        else: escaped.append(f"\\x{byte:02x}")
    return "".join(escaped)

def profile_mod_value(value):
    """Return the game-facing active_mods value for one visible mod card."""
    raw = str(value)
    raw_file, raw_name = (raw.split("|", 1) + [raw])[:2] if "|" in raw else (raw, raw)
    file_name = unescape_sii_string(raw_file).replace("\\", "/").rsplit("/", 1)[-1]
    # The profile stores package names, not archive filenames.  Strip every
    # known archive suffix so both ``foo.scs`` and ``foo.scs.zip`` become foo.
    while Path(file_name).suffix.casefold() in ARCHIVE_SUFFIXES:
        file_name = Path(file_name).stem
    display_name = unescape_sii_string(raw_name)
    return sii_escape_string(file_name) + "|" + sii_escape_string(display_name)

def save_manager_mod_order(game_path, directory, values):
    """Persist the visible order only after the explicit Save click."""
    profile = profile_path(game_path, directory)
    if not profile: return None, "profile_not_found"
    enabled, error = text_save_format_enabled(game_path)
    if not enabled: return None, error
    if not isinstance(values, list): return None, "invalid_mod_order"
    normalized = [profile_mod_value(value) for value in values if isinstance(value, str)]
    if len(normalized) != len(values): return None, "invalid_mod_order"
    return write_mod_values(profile, normalized, f"{directory}-profile-mod-manager")

def saved_mod_groups():
    value = load_resource_json("mod_groups.json", {})
    groups = value.get("groups", {}) if isinstance(value, dict) else {}
    cleaned = {}
    for file, group_list in groups.items():
        if not isinstance(file, str): continue
        # Accept files saved by the previous one-group-per-mod version.
        values = [group_list] if isinstance(group_list, str) else group_list if isinstance(group_list, list) else []
        values = [str(group).strip() for group in values if isinstance(group, str) and str(group).strip()][:12]
        if values: cleaned[file.casefold()] = list(dict.fromkeys(values))
    return cleaned

def save_mod_groups(value):
    if not isinstance(value, dict): return None, "invalid_mod_groups"
    groups = {}
    for file, group_list in value.items():
        if not isinstance(file, str): continue
        file = Path(file).name
        values = [group_list] if isinstance(group_list, str) else group_list if isinstance(group_list, list) else []
        values = [str(group).strip() for group in values if isinstance(group, str) and str(group).strip() and len(str(group).strip()) <= 80]
        if file and len(file) <= 512 and values:
            groups[file.casefold()] = list(dict.fromkeys(values))[:12]
    save_resource_json("mod_groups.json", {"groups": groups})
    return {"groups": groups}, None

VIEW_FILTER_KEYS = ("author", "version", "compatible", "dlc", "status")
VIEW_SORTS = {"created_desc", "created_asc", "name_asc", "name_desc", "size_desc", "size_asc", "categories_asc", "categories_desc"}

def clean_view_filters(value):
    """Keep only the compact, display-only filter state from the page."""
    value = value if isinstance(value, dict) else {}
    result = {}
    for key in VIEW_FILTER_KEYS:
        entries = value.get(key, [])
        if not isinstance(entries, list): entries = []
        result[key] = list(dict.fromkeys(str(item).strip() for item in entries if isinstance(item, str) and str(item).strip()))[:100]
    result["no_manifest"] = bool(value.get("no_manifest", False))
    return result

def clean_view_scope(value, include_sort=False):
    value = value if isinstance(value, dict) else {}
    result = {
        "group": str(value.get("group", "")).strip()[:80],
        "filters": clean_view_filters(value.get("filters")),
    }
    if include_sort:
        sort = str(value.get("sort", "created_desc"))
        result["sort"] = sort if sort in VIEW_SORTS else "created_desc"
    return result

def saved_mod_view_settings():
    value = load_resource_json("mod_view_settings.json", {})
    value = value if isinstance(value, dict) else {}
    raw_profiles = value.get("profiles", {})
    profiles = {}
    if isinstance(raw_profiles, dict):
        for directory, scope in raw_profiles.items():
            if isinstance(directory, str) and directory and len(directory) <= 512:
                profiles[directory] = clean_view_scope(scope)
    return {"folder": clean_view_scope(value.get("folder"), include_sort=True), "profiles": profiles}

def save_mod_view_settings(value):
    if not isinstance(value, dict): return None, "invalid_view_settings"
    raw_profiles = value.get("profiles", {})
    profiles = {}
    if isinstance(raw_profiles, dict):
        for directory, scope in raw_profiles.items():
            if isinstance(directory, str) and directory and len(directory) <= 512:
                profiles[directory] = clean_view_scope(scope)
    saved = {"folder": clean_view_scope(value.get("folder"), include_sort=True), "profiles": profiles}
    save_resource_json("mod_view_settings.json", saved)
    return {"settings": saved}, None

def report_icon(value):
    """Embed a local icon when it is reasonably small, so the report is portable."""
    try:
        path = Path(unquote(urlparse(str(value)).path.lstrip("/"))) if value else Path()
        if not path.is_file():
            logic_file = Path(globals().get("__file__", ""))
            candidates = ([logic_file.with_name("default.webp")] if logic_file.name else []) + [Path.cwd() / "default.webp", Path.cwd() / "source" / "default.webp"]
            path = next((candidate for candidate in candidates if candidate.is_file()), Path())
        if not path.is_file() or path.stat().st_size > 512 * 1024: return ""
        suffix = path.suffix.casefold()
        mime = {".webp": "image/webp", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}.get(suffix)
        if not mime: return ""
        return f"data:{mime};base64," + base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError: return ""

def export_mod_report(mods, groups, language, profile_name=""):
    if not isinstance(mods, list): return None, "invalid_export"
    ru = language == "ru"; title = "Порядок загрузки модов ETS2" if ru else "ETS2 mod load order"
    rows = []
    for index, mod in enumerate(mods, 1):
        if not isinstance(mod, dict): continue
        value = lambda key: html_lib.escape(str(mod.get(key) or "—"))
        file = str(mod.get("file") or "")
        assigned = groups.get(file.casefold(), []) if isinstance(groups, dict) else []
        assigned = assigned if isinstance(assigned, list) else [assigned]
        labels = ", ".join(html_lib.escape(str(item)) for item in assigned if item) or "—"
        icon = report_icon(mod.get("icon")); image = f'<img src="{icon}" alt="">' if icon else '<div class="placeholder">MOD</div>'
        rows.append(f'<article class="mod">{image}<div><h2>{index}. {value("name")}</h2><p class="file">{value("file")}</p><dl><dt>{"Version" if not ru else "Версия"}</dt><dd>{value("version")}</dd><dt>{"Author" if not ru else "Автор"}</dt><dd>{value("author")}</dd><dt>{"Compatible" if not ru else "Совместимость"}</dt><dd>{html_lib.escape(", ".join(map(str, mod.get("compatible_versions") or [])) or "—")}</dd><dt>DLC</dt><dd>{html_lib.escape(", ".join(map(str, mod.get("dlc") or [])) or "—")}</dd><dt>{"Groups" if not ru else "Группы"}</dt><dd>{labels}</dd></dl></div></article>')
    document = f"""<!doctype html><html lang="{'ru' if ru else 'en'}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>body{{margin:0;padding:30px;background:#10151d;color:#eaf0f7;font:15px/1.45 system-ui,sans-serif}}main{{max-width:1050px;margin:auto}}h1{{margin:0 0 6px;color:#ff8a54}}.lead{{margin:0 0 24px;color:#aebaca}}.mod{{display:flex;align-items:center;gap:18px;margin:12px 0;padding:16px;border:1px solid #34445a;border-radius:14px;background:linear-gradient(135deg,#202733,#171b22)}}img,.placeholder{{flex:0 0 138px;width:138px;height:81px;align-self:center;object-fit:contain;border:1px solid #4b5c70;border-radius:10px;background:#0f151d}}.placeholder{{display:grid;place-items:center;color:#ff8a54;font-weight:700}}h2{{margin:0;color:#fff;font-size:18px}}.file{{margin:3px 0 12px;color:#ffb18d;font-family:Consolas,monospace}}dl{{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;margin:0}}dt{{color:#91a6bb}}dd{{margin:0;word-break:break-word}}@media(max-width:560px){{body{{padding:14px}}.mod{{gap:12px}}img,.placeholder{{flex-basis:88px;width:88px;height:52px}}dl{{grid-template-columns:1fr}}}}</style><main><h1>{title}</h1><p class="lead">{"Экспортировано из SCS Tools Manager" if ru else "Exported from SCS Tools Manager"} · {len(rows)}</p>{''.join(rows) or '<p>—</p>'}</main></html>"""
    # An export is also a portable load-order preset.  Keeping the payload in
    # the HTML makes it useful on another computer without any sidecar files.
    preset = json.dumps({"format": "scs-tools-profile-mod-manager-preset", "mods": [str(mod.get("sii_value") or f"{mod.get('file') or ''}|{mod.get('name') or mod.get('file') or ''}") for mod in mods if isinstance(mod, dict)]}, ensure_ascii=False).replace("<", "\\u003c")
    document = document.replace("</html>", f'<script id="pmm-preset" type="application/json">{preset}</script></html>')
    try:
        name = re.sub(r'[\\/:*?"<>|\x00-\x1f]+', '_', str(profile_name)).strip(' ._') or "profile"
        target = storage_root() / f"{name}_export_{time.strftime('%Y%m%d_%H%M%S')}.html"
        target.write_text(document, encoding="utf-8")
        return {"path": str(target)}, None
    except OSError: return None, "export_failed"

def import_html_preset(path):
    """Read the machine-portable preset embedded into an exported report."""
    try:
        source = Path(str(path)).expanduser()
        if source.suffix.casefold() not in (".html", ".htm") or not source.is_file(): return None, "invalid_preset_file"
        text = source.read_text(encoding="utf-8-sig", errors="replace")
        match = re.search(r'<script\s+[^>]*id=["\']pmm-preset["\'][^>]*>(.*?)</script\s*>', text, re.I | re.S)
        if not match: return None, "invalid_preset_file"
        value = json.loads(match.group(1)); mods = value.get("mods") if isinstance(value, dict) else None
        if not isinstance(mods, list): return None, "invalid_preset_file"
        return {"mods": [str(item) for item in mods if isinstance(item, str)]}, None
    except (OSError, ValueError, json.JSONDecodeError): return None, "invalid_preset_file"

def profile_storage_key(directory):
    return hashlib.sha256(str(directory).encode("utf-8", "replace")).hexdigest()[:20]

def order_presets(directory):
    saved = load_resource_json("order_presets.json", {})
    records = saved.get("profiles", {}).get(str(directory), []) if isinstance(saved, dict) else []
    return [item for item in records if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("mods"), list)]

def save_order_preset(directory, name, mods):
    if not isinstance(mods, list): return None, "invalid_mod_order"
    name = str(name or "").strip()
    if not name or len(name) > 80: return None, "invalid_preset_name"
    saved = load_resource_json("order_presets.json", {})
    if not isinstance(saved, dict): saved = {}
    profiles_data = saved.setdefault("profiles", {})
    current = [item for item in profiles_data.get(str(directory), []) if isinstance(item, dict) and item.get("name") != name]
    current.append({"name": name, "mods": [str(item) for item in mods if isinstance(item, str)], "created": time.strftime("%Y-%m-%d %H:%M:%S")})
    profiles_data[str(directory)] = current[-50:]
    save_resource_json("order_presets.json", saved)
    return {"presets": profiles_data[str(directory)]}, None

def delete_order_preset(directory, name):
    saved = load_resource_json("order_presets.json", {})
    if not isinstance(saved, dict): return {"presets": []}, None
    profiles_data = saved.setdefault("profiles", {})
    profiles_data[str(directory)] = [item for item in profiles_data.get(str(directory), []) if not isinstance(item, dict) or item.get("name") != name]
    save_resource_json("order_presets.json", saved)
    return {"presets": profiles_data[str(directory)]}, None

def autosave_directory():
    target = storage_root() / "autosave"; target.mkdir(parents=True, exist_ok=True); return target

def list_order_autosaves(directory):
    prefix = profile_storage_key(directory) + "_"; records = []
    for path in sorted(autosave_directory().glob(prefix + "*.json"), key=lambda item: item.name, reverse=True)[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
            if isinstance(value, dict) and isinstance(value.get("mods"), list): records.append({"file": path.name, "created": value.get("created", ""), "description": value.get("description", ""), "mods": value["mods"], "actions": value.get("actions", [])})
        except (OSError, ValueError): pass
    return records

def mod_order_actions(before, after):
    """Describe a load-order change in terms a person can immediately read."""
    before = [str(item) for item in before if isinstance(item, str)]
    after = [str(item) for item in after if isinstance(item, str)]
    before_positions = {item: index for index, item in enumerate(before)}
    after_positions = {item: index for index, item in enumerate(after)}
    label = lambda item: (item.split("|", 1)[1].strip() if "|" in item and item.split("|", 1)[1].strip() else item.split("|", 1)[0])
    actions = {}
    for index, item in enumerate(after):
        name = label(item)
        if item not in before_positions:
            actions[name] = {"Added": True, "position": index + 1}
        elif before_positions[item] != index:
            # Positive values mean the mod moved closer to the top.
            delta = before_positions[item] - index
            actions[name] = {"position": delta}
    for item in before:
        if item not in after_positions:
            actions[label(item)] = {"Deleted": True}
    return actions

def merge_mod_actions(first, second):
    """Merge repeated edits of the same mod into one compact journal entry."""
    merged = dict(first) if isinstance(first, dict) else {}
    for name, change in (second.items() if isinstance(second, dict) else []):
        if not isinstance(change, dict): continue
        old = merged.get(name, {})
        if "position" in old and "position" in change and not old.get("Added") and not old.get("Deleted") and not change.get("Added") and not change.get("Deleted"):
            merged[name] = {"position": int(old["position"]) + int(change["position"])}
        else:
            merged[name] = dict(change)
    return {name: change for name, change in merged.items() if not (set(change) == {"position"} and not change["position"])}

def autosave_order(directory, mods, description, actions=None):
    if not isinstance(mods, list): return None, "invalid_mod_order"
    created = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        current = [str(item) for item in mods if isinstance(item, str)]
        data = order_history_data(); entry = data.setdefault("profiles", {}).setdefault(str(directory), {"last": [], "items": []})
        previous = entry.get("autosave_last", entry.get("last", []))
        actions = actions if isinstance(actions, dict) else mod_order_actions(previous, current)
        prefix = profile_storage_key(directory) + "_"; recent = sorted(autosave_directory().glob(prefix + "*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        target = recent[0] if recent and time.time() - recent[0].stat().st_mtime < 3 else autosave_directory() / f"{prefix}{time.strftime('%Y%m%d_%H%M%S')}_{time.time_ns() % 1000000}.json"
        if target.exists():
            try:
                old = json.loads(target.read_text(encoding="utf-8-sig")); actions = merge_mod_actions(old.get("actions"), actions); created = old.get("created", created)
            except (OSError, ValueError): pass
        target.write_text(json.dumps({"created": created, "updated_unix": time.time(), "description": str(description or "Changed load order"), "mods": current, "actions": actions}, ensure_ascii=False, indent=2), encoding="utf-8")
        if actions:
            items = entry.setdefault("items", [])
            if items and items[-1].get("action") == "Unsaved changes" and time.time() - float(items[-1].get("updated_unix", 0)) < 3:
                items[-1].update({"after": current, "actions": merge_mod_actions(items[-1].get("actions"), actions), "updated_unix": time.time()})
            else:
                items.append({"created": created, "updated_unix": time.time(), "action": "Unsaved changes", "before": previous, "after": current, "actions": actions})
            entry["items"] = entry["items"][-100:]
        entry["autosave_last"] = current; save_resource_json("order_history.json", data)
        return {"autosaves": list_order_autosaves(directory), "history": entry.get("items", [])}, None
    except OSError: return None, "autosave_failed"

def clear_order_autosaves(directory):
    prefix = profile_storage_key(directory) + "_"
    for path in autosave_directory().glob(prefix + "*.json"):
        try: path.unlink()
        except OSError: pass
    data = order_history_data(); entry = data.setdefault("profiles", {}).setdefault(str(directory), {"last": [], "items": []}); entry["autosave_last"] = entry.get("last", []); save_resource_json("order_history.json", data)
    return {"autosaves": []}, None

def order_history_data():
    value = load_resource_json("order_history.json", {})
    return value if isinstance(value, dict) else {}

def record_order_history(directory, action, before, after, actions=None):
    data = order_history_data(); profiles_data = data.setdefault("profiles", {}); entry = profiles_data.setdefault(str(directory), {"last": [], "items": []})
    if before != after:
        entry.setdefault("items", []).append({"created": time.strftime("%Y-%m-%d %H:%M:%S"), "action": action, "before": before, "after": after, "actions": actions if isinstance(actions, dict) else mod_order_actions(before, after)})
        entry["items"] = entry["items"][-100:]
    entry["last"] = after
    entry["autosave_last"] = after
    save_resource_json("order_history.json", data)
    return entry.get("items", [])

def track_external_order_change(directory, current):
    data = order_history_data(); entry = data.setdefault("profiles", {}).setdefault(str(directory), {"last": [], "items": []}); previous = entry.get("last", [])
    if previous and previous != current: record_order_history(directory, "Changed in game", previous, current)
    elif not previous:
        entry["last"] = current; save_resource_json("order_history.json", data)
    return order_history_data().get("profiles", {}).get(str(directory), {}).get("items", [])

def undo_order_history(directory):
    data = order_history_data(); entry = data.setdefault("profiles", {}).setdefault(str(directory), {"last": [], "items": []}); items = entry.setdefault("items", [])
    removed = items.pop() if items else None; save_resource_json("order_history.json", data)
    return {"history": items, "entry": removed}, None

def redo_order_history(directory, item):
    if not isinstance(item, dict): return None, "invalid_history_entry"
    data = order_history_data(); entry = data.setdefault("profiles", {}).setdefault(str(directory), {"last": [], "items": []}); entry.setdefault("items", []).append(item); entry["items"] = entry["items"][-100:]; save_resource_json("order_history.json", data)
    return {"history": entry["items"]}, None

def main():
    try: data = json.loads(os.environ.get("SCS_TOOL_INPUT", "{}"))
    except json.JSONDecodeError: data = {}
    action = data.get("action")
    if action == "defaults":
        settings = load_resource_json("settings.json", {})
        game_path = settings.get("game_path") or default_game_path()
        found, _error = profiles(game_path)
        return reply(status="defaults", game_path=game_path, profiles=found or [], groups=saved_mod_groups())
    game_path = str(data.get("game_path", "")).strip()
    if action == "scan_profiles":
        found, error = profiles(game_path)
        if error: return reply(status="error", action=action, code=error)
        save_resource_json("settings.json", {"game_path": game_path})
        return reply(status="ok", action=action, profiles=found)
    if action == "read_mods":
        try: value, error = manager_mods(game_path, str(data.get("profile_dir", "")))
        except Exception as error:
            return reply(status="error", action=action, code="generic", message=f"{type(error).__name__}: {error}")
        if error: return reply(status="error", action=action, code=error)
        directory = str(data.get("profile_dir", "")); current = [str(item.get("sii_value") or item.get("file")) for item in value.get("mods", [])]
        return reply(status="ok", action=action, autosaves=list_order_autosaves(directory), presets=order_presets(directory), history=track_external_order_change(directory, current), **value)
    if action == "load_mod_metadata":
        try:
            items, error = load_mod_metadata(game_path, data.get("files", []), data.get("retry_icons", False), data.get("verify_cache", False))
        except Exception as error:
            return reply(status="error", action=action, code="generic", message=f"{type(error).__name__}: {error}")
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, metadata=items)
    if action == "save_mod_order":
        try:
            value, error = save_manager_mod_order(game_path, str(data.get("profile_dir", "")), data.get("mods"))
        except Exception as error:
            return reply(status="error", action=action, code="generic", message=f"{type(error).__name__}: {error}")
        if error: return reply(status="error", action=action, code=error)
        directory = str(data.get("profile_dir", "")); before = order_history_data().get("profiles", {}).get(directory, {}).get("last", [])
        after = [str(item) for item in data.get("mods", []) if isinstance(item, str)]
        history_label = str(data.get("history_action") or "Saved in Profile Mod Manager")
        history = record_order_history(directory, history_label, before, after, data.get("actions")); clear_order_autosaves(directory)
        return reply(status="ok", action=action, history=history, **value)
    if action == "load_mod_groups":
        return reply(status="ok", action=action, groups=saved_mod_groups())
    if action == "save_mod_groups":
        value, error = save_mod_groups(data.get("groups"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "load_mod_view_settings":
        return reply(status="ok", action=action, settings=saved_mod_view_settings())
    if action == "save_mod_view_settings":
        value, error = save_mod_view_settings(data.get("settings"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "export_mod_report":
        value, error = export_mod_report(data.get("mods"), data.get("groups", {}), str(data.get("language", "en")), str(data.get("profile_name", "")))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "import_html_preset":
        value, error = import_html_preset(data.get("path", ""))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    directory = str(data.get("profile_dir", ""))
    if action == "list_order_presets": return reply(status="ok", action=action, presets=order_presets(directory))
    if action == "save_order_preset":
        value, error = save_order_preset(directory, data.get("name"), data.get("mods"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "delete_order_preset":
        value, error = delete_order_preset(directory, str(data.get("name", "")))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "autosave_order":
        value, error = autosave_order(directory, data.get("mods"), data.get("description"), data.get("actions"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "clear_order_autosaves":
        value, error = clear_order_autosaves(directory)
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "list_order_history": return reply(status="ok", action=action, history=order_history_data().get("profiles", {}).get(directory, {}).get("items", []))
    if action == "undo_order_history":
        value, error = undo_order_history(directory)
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "redo_order_history":
        value, error = redo_order_history(directory, data.get("entry"))
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    return reply(status="error", action=action, code="generic")

if __name__ == "__main__": main()

# analyzer.py
import os, re, subprocess, hashlib, zipfile
from androguard.core.bytecodes.apk import APK   # ✅ Correct import

# Simple known-good map (expand with real bank package names + certs)
KNOWN_APPS = {
    # 'com.example.bank': { 'name': 'Example Bank', 'cert_sha256': 'abcd...'},
}

SUSPICIOUS_PERMS = {
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.SYSTEM_ALERT_WINDOW",  # overlays
    "android.permission.BIND_ACCESSIBILITY_SERVICE"
}

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def get_apksigner_fingerprint(apk_path):
    """Try apksigner --print-certs (requires Android build-tools installed)."""
    try:
        res = subprocess.run(
            ["apksigner", "verify", "--print-certs", apk_path],
            capture_output=True, text=True, check=True
        )
        out = res.stdout + res.stderr
        m = re.search(r"SHA-256.*?:\s*([0-9A-Fa-f:]+)", out)
        if m:
            return m.group(1).replace(":", "").lower()
    except Exception:
        return None
    return None

def get_fallback_cert_fingerprint(apk_path):
    """Fallback: hash the first META-INF/*.RSA/DSA/EC entry from APK zip."""
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            candidates = [
                n for n in z.namelist()
                if n.upper().startswith("META-INF/")
                and n.split('.')[-1].upper() in ("RSA", "DSA", "EC")
            ]
            if not candidates:
                return None
            data = z.read(candidates[0])
            return hashlib.sha256(data).hexdigest()
    except Exception:
        return None

def analyze_apk(apk_path):
    report = {}
    report['file_sha256'] = sha256_file(apk_path)
    report['filename'] = os.path.basename(apk_path)

    # parse APK with androguard
    a = APK(apk_path)
    report['package'] = a.get_package()
    report['app_name'] = a.get_app_name()
    report['version_name'] = a.get_androidversion_name()
    report['permissions'] = a.get_permissions() or []

    # certificate fingerprint (try apksigner then fallback)
    cert_fp = get_apksigner_fingerprint(apk_path)
    if not cert_fp:
        cert_fp = get_fallback_cert_fingerprint(apk_path)
    report['cert_sha256'] = cert_fp

    # ---- heuristics ----
    reasons = []
    score = 0

    # suspicious permissions
    found_suspicious = [p for p in report['permissions'] if p in SUSPICIOUS_PERMS]
    if found_suspicious:
        reasons.append(f"Suspicious permissions: {found_suspicious}")
        score += 15 * len(found_suspicious)

    # package name vs app name
    pkg = report['package'] or ""
    for bankname in ("bank", "hdfc", "icici", "sbi", "axis", "kbf", "yesbank", "paytm"):
        if bankname in (report['app_name'] or "").lower() and bankname not in pkg.lower():
            reasons.append(f"App name contains '{bankname}' but package name differs.")
            score += 20
            break

    # certificate mismatch
    if pkg in KNOWN_APPS:
        known_cert = KNOWN_APPS[pkg].get('cert_sha256')
        if known_cert and cert_fp and known_cert.lower() != cert_fp.lower():
            reasons.append("Certificate fingerprint mismatch for known package.")
            score += 40
    else:
        for bn in ("bank", "netbank", "mobilebank"):
            if bn in pkg.lower():
                reasons.append("Package name contains bank-like token but not in known list.")
                score += 20
                break

    # DEX heuristic
    dex_len = len(a.get_dex_names() or [])
    if dex_len == 0:
        reasons.append("No DEX found in APK.")
        score += 30

    # suspicious URLs in strings
    strings = a.get_strings()
    suspicious_urls = [
        s for s in strings if ("http://" in s or "https://" in s) and
        any(x in s.lower() for x in ("bit.ly", "ngrok", "herokuapp", "telegr", "discordapp", "webhook"))
    ]
    if suspicious_urls:
        reasons.append(f"Suspicious URLs found: {suspicious_urls[:3]}")
        score += 30

    # cap score
    report['score'] = min(score, 100)
    if score >= 60:
        report['risk'] = "Malicious"
    elif score >= 30:
        report['risk'] = "Suspicious"
    else:
        report['risk'] = "Likely Safe"

    report['reasons'] = reasons
    return report

if __name__ == "__main__":
    import sys, json
    if len(sys.argv) >= 2:
        p = sys.argv[1]
        r = analyze_apk(p)
        print(json.dumps(r, indent=2))
    else:
        print("Usage: python analyzer.py <app.apk>")

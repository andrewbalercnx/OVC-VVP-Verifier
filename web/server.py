#!/usr/bin/env python3
"""
Lightweight server for the VVP Parser UI.
Does not require pysodium/libsodium - just serves the UI and proxies dossier fetches.
"""
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.request
import urllib.error
import ssl
import os

MOCK_DOSSIER = [
    {
        "v": "ACDC10JSON000000_",
        "d": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        "i": "EMyYnLzlJDJskqojipIMivAKHWeZofhWiYjB79uszynS",
        "s": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        "a": {
            "d": "EGZ_DdmzryjQOtOdQauTm_YxggbVM7EWelk8IBxsnC-d",
            "i": "EMyYnLzlJDJskqojipIMivAKHWeZofhWiYjB79uszynS",
            "dt": "2025-01-20T12:00:00.000000+00:00",
            "LEI": "254900OPPU84GM83MG36",
            "legalName": "Orange France Telecom SA",
            "tn": ["330123456791"],
            "country": "FR",
            "spCode": "ORANGE-FR"
        },
        "e": {
            "d": "EKE3E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4",
            "auth": {
                "n": "EAuth00000000000000000000000000000000000000",
                "s": "ESchema0000000000000000000000000000000000"
            }
        },
        "r": {
            "d": "ERules0000000000000000000000000000000000000",
            "usageRules": {
                "validityPeriod": 300,
                "oneTimeUse": False
            }
        }
    },
    {
        "v": "ACDC10JSON000000_",
        "d": "EAuth00000000000000000000000000000000000000",
        "i": "ERegulatoryAuthority000000000000000000000",
        "s": "ESchema0000000000000000000000000000000000",
        "a": {
            "d": "EAttr00000000000000000000000000000000000",
            "i": "EMyYnLzlJDJskqojipIMivAKHWeZofhWiYjB79uszynS",
            "dt": "2024-06-01T00:00:00.000000+00:00",
            "authorizedTNs": ["33*"],
            "authorizationType": "ORIGINATION",
            "jurisdiction": "FR",
            "regulatoryBody": "ARCEP"
        }
    }
]


class VVPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve from web/ directory
        super().__init__(*args, directory=os.path.dirname(__file__), **kwargs)

    def do_GET(self):
        # Serve mock dossier
        if self.path == "/mock-dossier":
            self._send_json(MOCK_DOSSIER)
        else:
            super().do_GET()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        if self.path == "/proxy-fetch":
            try:
                req_body = json.loads(post_data)
                url = req_body.get("url", "")

                if not url:
                    self._send_json({"success": False, "error": "No URL provided"})
                    return

                # Fetch the URL (with SSL verification disabled for dev)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={"User-Agent": "VVP-Parser/1.0"})
                with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                    content_type = response.headers.get("Content-Type", "")
                    data = response.read().decode("utf-8")

                    # Try to parse as JSON
                    try:
                        parsed = json.loads(data)
                        self._send_json({
                            "success": True,
                            "data": parsed,
                            "content_type": content_type
                        })
                    except json.JSONDecodeError:
                        # Return raw text
                        self._send_json({
                            "success": True,
                            "data": data,
                            "content_type": content_type
                        })

            except urllib.error.URLError as e:
                self._send_json({"success": False, "error": f"URL error: {e.reason}"})
            except urllib.error.HTTPError as e:
                self._send_json({"success": False, "error": f"HTTP {e.code}: {e.reason}"})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})

        elif self.path == "/check-revocation":
            # Query KERI witnesses for credential revocation status
            try:
                req_body = json.loads(post_data)
                cred_said = req_body.get("credential_said", "")
                registry_said = req_body.get("registry_said")
                oobi_url = req_body.get("oobi_url")

                if not cred_said:
                    self._send_json({"success": False, "error": "No credential_said provided"})
                    return

                print(f"\n[TEL] === Checking revocation for credential ===")
                print(f"[TEL] Credential SAID: {cred_said[:24]}...")
                if registry_said:
                    print(f"[TEL] Registry SAID: {registry_said[:24]}...")
                if oobi_url:
                    print(f"[TEL] OOBI URL: {oobi_url[:60]}...")

                result = self._check_revocation_status(cred_said, registry_said, oobi_url)
                print(f"[TEL] Final result: {result['status']}")
                self._send_json(result)

            except Exception as e:
                self._send_json({"success": False, "status": "ERROR", "error": str(e)})

        else:
            self.send_error(404, "Not found")

    def _check_revocation_status(self, cred_said, registry_said, oobi_url):
        """
        Query KERI infrastructure for credential revocation status.

        Tries multiple approaches:
        1. OOBI URL if provided (extracts witness endpoint)
        2. Known witness endpoints
        3. Returns UNKNOWN if no TEL data found
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Build list of endpoints to try
        endpoints_to_try = []

        # If OOBI URL provided, extract base and try TEL endpoints
        if oobi_url:
            from urllib.parse import urlparse
            parsed = urlparse(oobi_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            endpoints_to_try.extend([
                f"{base_url}/tels/{registry_said or cred_said}",
                f"{base_url}/credentials/{cred_said}",
                f"{base_url}/oobi/{cred_said}/tels",
            ])

        # GLEIF KERIA testnet witnesses
        known_witnesses = [
            "https://wit1.testnet.gleif.org:5641",
            "https://wit2.testnet.gleif.org:5642",
            "https://wit3.testnet.gleif.org:5643",
        ]

        # Provenant dev witnesses
        provenant_witnesses = [
            "http://witness1.dev.provenant.net:5631",
            "http://witness2.dev.provenant.net:5631",
            "http://witness3.dev.provenant.net:5631",
        ]

        for witness in known_witnesses:
            endpoints_to_try.append(f"{witness}/tels/{registry_said or cred_said}")

        for witness in provenant_witnesses:
            endpoints_to_try.append(f"{witness}/tels/{registry_said or cred_said}")

        # Try each endpoint
        for url in endpoints_to_try:
            print(f"[TEL] Querying: {url}")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "VVP-Parser/1.0"})
                with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                    status_code = response.getcode()
                    data = response.read().decode("utf-8")
                    print(f"[TEL] Response from {url}: HTTP {status_code}, {len(data)} bytes")
                    result = self._parse_tel_response(data, cred_said, registry_said, url)
                    if result["status"] != "UNKNOWN":
                        print(f"[TEL] Found status: {result['status']}")
                        return result
                    else:
                        print(f"[TEL] No TEL events found in response")
            except urllib.error.HTTPError as e:
                print(f"[TEL] HTTP Error from {url}: {e.code} {e.reason}")
            except urllib.error.URLError as e:
                print(f"[TEL] URL Error from {url}: {e.reason}")
            except Exception as e:
                print(f"[TEL] Error from {url}: {type(e).__name__}: {e}")

        # No TEL data found from any source
        return {
            "success": True,
            "status": "UNKNOWN",
            "credential_said": cred_said,
            "registry_said": registry_said,
            "source": "none",
            "error": "No TEL data found from any configured witness"
        }

    def _parse_tel_response(self, data, cred_said, registry_said, source):
        """Parse TEL response and determine revocation status."""
        events = self._extract_tel_events(data)

        if not events:
            return {
                "success": True,
                "status": "UNKNOWN",
                "credential_said": cred_said,
                "registry_said": registry_said,
                "source": source
            }

        # Find events for this credential
        cred_events = [e for e in events if e.get("i") == cred_said]
        if not cred_events and registry_said:
            cred_events = [e for e in events if e.get("ri") == registry_said]
        if not cred_events:
            cred_events = events

        # Sort by sequence
        cred_events.sort(key=lambda e: int(e.get("s", 0)))

        # Find issuance and revocation
        issuance = None
        revocation = None

        for event in cred_events:
            t = event.get("t")
            if t in ("iss", "bis"):
                issuance = event
            elif t in ("rev", "brv"):
                revocation = event

        # Build response
        result = {
            "success": True,
            "credential_said": cred_said,
            "registry_said": registry_said,
            "source": source
        }

        if revocation:
            result["status"] = "REVOKED"
            result["revocation"] = {
                "datetime": revocation.get("dt"),
                "sequence": int(revocation.get("s", 0)),
                "type": revocation.get("t")
            }
        elif issuance:
            result["status"] = "ACTIVE"
        else:
            result["status"] = "UNKNOWN"

        if issuance:
            result["issuance"] = {
                "datetime": issuance.get("dt"),
                "sequence": int(issuance.get("s", 0)),
                "type": issuance.get("t")
            }

        return result

    def _extract_tel_events(self, data):
        """Extract TEL events from response (JSON or CESR)."""
        events = []

        # Try JSON first
        try:
            parsed = json.loads(data)
            if isinstance(parsed, list):
                for item in parsed:
                    if item.get("t") in ("iss", "rev", "bis", "brv"):
                        events.append(item)
            elif isinstance(parsed, dict) and parsed.get("t") in ("iss", "rev", "bis", "brv"):
                events.append(parsed)
            return events
        except json.JSONDecodeError:
            pass

        # Parse CESR stream
        pos = 0
        while True:
            match = data.find('{"v":"KERI', pos)
            if match == -1:
                break

            try:
                depth = 0
                start = match
                end = match

                for i in range(match, len(data)):
                    if data[i] == '{':
                        depth += 1
                    elif data[i] == '}':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break

                obj = json.loads(data[start:end])
                if obj.get("t") in ("iss", "rev", "bis", "brv"):
                    events.append(obj)
                pos = end
            except (json.JSONDecodeError, IndexError):
                pos = match + 1

        return events

    def _send_json(self, data):
        response = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response))
        self.end_headers()
        self.wfile.write(response)


if __name__ == "__main__":
    port = 8000
    server = HTTPServer(("127.0.0.1", port), VVPHandler)
    print(f"VVP Parser server running at http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")

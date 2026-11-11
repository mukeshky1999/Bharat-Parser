"""
Canonical Path Normalization Engine.
Phase 1, Module 1.1, Section 5: Translates extraction tool quirks and vendor prefixes into a unified path.
"""

import re
import unicodedata


class CanonicalPathNormalizer:
    """Enforces the 6-Step Canonical Path Normalization Rules."""

    VENDOR_PREFIX_REGEX = re.compile(
        r"^/(?:fs|root|Dump|files|[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}/root|[a-fA-F0-9]{40}/root)(?=/|$)",
        re.IGNORECASE
    )

    STORAGE_EMULATED_REGEX = re.compile(
        r"^/storage/emulated/(\d+)(?=/|$)"
    )

    def normalize_path(self, raw_path: str) -> str:
        """
        Normalizes any mobile extraction path to canonical device path.
        Applies:
        1. Slash & Unicode NFC normalization.
        2. Vendor wrapper prefix stripping (/fs/, /root/, /Dump/, /files/, etc.).
        3. iOS symlink rewriting (/var/ -> /private/var/).
        4. Android primary sandbox rewriting (/data/data/ -> /data/user/0/).
        5. Android shared storage rewriting (/sdcard/, /mnt/sdcard/, /storage/emulated/<user>/).
        """
        if not raw_path:
            return "/"

        # Step 1: Slash conversion and Unicode NFC
        path = raw_path.replace("\\", "/")
        path = re.sub(r"/+", "/", path)
        if not path.startswith("/"):
            path = "/" + path
        path = unicodedata.normalize("NFC", path)

        # Step 2: Strip vendor wrapper prefixes (e.g. /fs/, /root/, /Dump/, /files/)
        # Run in a loop in case multiple wrappers are chained (e.g. /fs/root/...)
        while True:
            match = self.VENDOR_PREFIX_REGEX.match(path)
            if match:
                stripped = path[match.end():]
                path = stripped if stripped.startswith("/") else ("/" + stripped if stripped else "/")
            else:
                break

        # Step 3: iOS symlink canonicalization (/var/ -> /private/var/, /tmp/ -> /private/tmp/)
        if path.startswith("/var/"):
            path = "/private" + path
        elif path == "/var":
            path = "/private/var"
        elif path.startswith("/tmp/"):
            path = "/private" + path
        elif path == "/tmp":
            path = "/private/tmp"

        # Step 4: Android primary sandbox canonicalization (/data/data/ -> /data/user/0/)
        if path.startswith("/data/data/"):
            path = "/data/user/0/" + path[len("/data/data/"):]
        elif path == "/data/data":
            path = "/data/user/0"

        # Step 5: Android shared storage canonicalization
        if path.startswith("/sdcard/"):
            path = "/data/media/0/" + path[len("/sdcard/"):]
        elif path == "/sdcard":
            path = "/data/media/0"
        elif path.startswith("/mnt/sdcard/"):
            path = "/data/media/0/" + path[len("/mnt/sdcard/"):]
        elif path == "/mnt/sdcard":
            path = "/data/media/0"
        else:
            emulated_match = self.STORAGE_EMULATED_REGEX.match(path)
            if emulated_match:
                user_id = emulated_match.group(1)
                rest = path[emulated_match.end():]
                if rest.startswith("/"):
                    rest = rest[1:]
                path = f"/data/media/{user_id}/{rest}" if rest else f"/data/media/{user_id}"

        # Ensure trailing slash stripped unless path is root '/'
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]

        return path

    def normalize_ios_domain(self, domain: str, relative_path: str) -> str:
        """
        Step 6: Maps iOS Logical Backup Manifest domain + relativePath to canonical iOS device path.
        """
        rel = relative_path.replace("\\", "/").lstrip("/")
        rel = re.sub(r"/+", "/", rel)

        if domain == "HomeDomain":
            return self.normalize_path(f"/private/var/mobile/{rel}")
        elif domain == "WirelessDomain":
            return self.normalize_path(f"/private/var/wireless/{rel}")
        elif domain == "CameraRollDomain":
            return self.normalize_path(f"/private/var/mobile/{rel}")
        elif domain == "SystemPreferencesDomain":
            return self.normalize_path(f"/private/var/preferences/{rel}")
        elif domain == "KeychainDomain":
            return self.normalize_path(f"/private/var/Keychains/{rel}")
        elif domain.startswith("AppDomain-"):
            bundle_id = domain[len("AppDomain-"):]
            return self.normalize_path(f"/private/var/mobile/Containers/Data/Application/{bundle_id}/{rel}")
        elif domain.startswith("AppDomainGroup-"):
            group_id = domain[len("AppDomainGroup-"):]
            return self.normalize_path(f"/private/var/mobile/Containers/Shared/AppGroup/{group_id}/{rel}")
        elif domain.startswith("AppDomainPlugin-"):
            plugin_id = domain[len("AppDomainPlugin-"):]
            return self.normalize_path(f"/private/var/mobile/Containers/Data/PluginKitPlugin/{plugin_id}/{rel}")
        elif domain == "MediaDomain":
            return self.normalize_path(f"/private/var/mobile/Media/{rel}")
        elif domain == "RootDomain":
            return self.normalize_path(f"/private/var/root/{rel}")
        else:
            return self.normalize_path(f"/private/var/mobile/Containers/Data/Application/{domain}/{rel}")

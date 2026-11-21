#!/usr/bin/env bash
set -euo pipefail

# Determine script and root directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=================================================================="
echo "🚀 Starting Hybrid Protected Release Build"
echo "=================================================================="

# Ensure Python environment is active or use python3
if [ -f "${ROOT_DIR}/.venv/bin/python" ]; then
    PYTHON="${ROOT_DIR}/.venv/bin/python"
else
    PYTHON="$(command -v python3)"
fi

echo "[1/6] Generating / Verifying Ed25519 Cryptographic Keys..."
"${PYTHON}" "${ROOT_DIR}/scripts/keygen.py" --secrets-dir "${ROOT_DIR}/.secrets"

PUB_KEY_FILE="${ROOT_DIR}/.secrets/public.pem"
if [ ! -f "${PUB_KEY_FILE}" ]; then
    echo "❌ Error: Public key ${PUB_KEY_FILE} not found!"
    exit 1
fi

BUILD_TMP="${ROOT_DIR}/build_tmp"
DIST_DIR="${ROOT_DIR}/dist/client_release"

echo "[2/6] Preparing Clean Temporary Build Directory: ${BUILD_TMP}..."
rm -rf "${BUILD_TMP}"
mkdir -p "${BUILD_TMP}/core_engine"

# Copy core engine source into build_tmp
cp -R "${ROOT_DIR}/core_engine/"* "${BUILD_TMP}/core_engine/"

echo "[3/6] Baking Public Key into license_guard.py before compilation..."
"${PYTHON}" -c "
import sys
pub_pem = open('${PUB_KEY_FILE}', 'r', encoding='utf-8').read().strip()
guard_path = '${BUILD_TMP}/core_engine/license_guard.py'
content = open(guard_path, 'r', encoding='utf-8').read()
target = 'PUBLIC_KEY_PEM = b\"\"\"__EMBEDDED_PUBLIC_KEY__\"\"\"'
replacement = f'PUBLIC_KEY_PEM = b\"\"\"\\\n{pub_pem}\\\n\"\"\"'
if target not in content:
    print('Error: Target placeholder not found in license_guard.py', file=sys.stderr)
    sys.exit(1)
new_content = content.replace(target, replacement)
open(guard_path, 'w', encoding='utf-8').write(new_content)
print('  -> Public key successfully baked into build_tmp/core_engine/license_guard.py')
"

echo "[4/6] Compiling Core Engine to Native Binaries with Cython..."
# Create temporary setup.py in build_tmp
cat << 'EOF' > "${BUILD_TMP}/setup.py"
from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension("core_engine.license_guard", ["core_engine/license_guard.py"]),
    Extension("core_engine.pricing_engine", ["core_engine/pricing_engine.py"]),
]

setup(
    name="core_engine",
    ext_modules=cythonize(
        extensions,
        compiler_directives={"language_level": "3"},
        quiet=False
    ),
)
EOF

(
    cd "${BUILD_TMP}"
    "${PYTHON}" setup.py build_ext --inplace
)

echo "[5/6] Assembling Protected Client Release in: ${DIST_DIR}..."
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}/core_engine"
mkdir -p "${DIST_DIR}/app_wrapper"

# Copy ONLY compiled .so / .pyd binaries into release core_engine/
find "${BUILD_TMP}/core_engine" -type f \( -name "*.so" -o -name "*.pyd" \) -exec cp {} "${DIST_DIR}/core_engine/" \;

# Create empty __init__.py in release core_engine/
touch "${DIST_DIR}/core_engine/__init__.py"

# Copy client app wrapper, templates, sample orders, requirements
cp -R "${ROOT_DIR}/app_wrapper/"* "${DIST_DIR}/app_wrapper/"
cp "${ROOT_DIR}/requirements.txt" "${DIST_DIR}/requirements.txt"

# Clean up any cached pycache in dist
find "${DIST_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Generate valid 30-day license for release
echo "Generating valid 30-day release license.key bound to current hostname..."
"${PYTHON}" "${ROOT_DIR}/scripts/sign_license.py" \
    --client "Acme Global Enterprise Inc." \
    --tier "enterprise" \
    --days 30 \
    --host "$(hostname)" \
    --private-key "${ROOT_DIR}/.secrets/private.pem" \
    --out "${DIST_DIR}/license.key"

# Clean temporary build directory
rm -rf "${BUILD_TMP}"

echo "[6/6] Executing Strict Release Audit Check on ${DIST_DIR}/core_engine/..."
AUDIT_FAILED=0

# Check for compiled binaries
SO_COUNT=$(find "${DIST_DIR}/core_engine" -type f \( -name "*.so" -o -name "*.pyd" \) | wc -l | tr -d ' ')
if [ "${SO_COUNT}" -lt 2 ]; then
    echo "❌ AUDIT FAILED: Expected at least 2 compiled binary files in core_engine, found ${SO_COUNT}!"
    AUDIT_FAILED=1
else
    echo "✅ Native binary check passed: Found ${SO_COUNT} compiled libraries:"
    find "${DIST_DIR}/core_engine" -type f \( -name "*.so" -o -name "*.pyd" \) -exec basename {} \; | sed 's/^/     - /'
fi

# Check for disallowed files (*.c, *.pem, *.map, *.pyx, non-empty *.py)
DISALLOWED_FILES=$(find "${DIST_DIR}/core_engine" -type f \( -name "*.c" -o -name "*.pem" -o -name "*.map" -o -name "*.pyx" \))
if [ -n "${DISALLOWED_FILES}" ]; then
    echo "❌ AUDIT FAILED: Found prohibited source/key files in release core_engine/:"
    echo "${DISALLOWED_FILES}"
    AUDIT_FAILED=1
fi

# Check for non-empty .py files
NON_EMPTY_PY=$(find "${DIST_DIR}/core_engine" -type f -name "*.py" ! -name "__init__.py")
if [ -n "${NON_EMPTY_PY}" ]; then
    echo "❌ AUDIT FAILED: Found .py files other than __init__.py in release core_engine/:"
    echo "${NON_EMPTY_PY}"
    AUDIT_FAILED=1
fi

# Check __init__.py size (must be 0 bytes or empty)
INIT_SIZE=$(wc -c < "${DIST_DIR}/core_engine/__init__.py" | tr -d ' ')
if [ "${INIT_SIZE}" -gt 100 ]; then
    echo "❌ AUDIT FAILED: __init__.py in release core_engine/ is unexpectedly non-empty (${INIT_SIZE} bytes)!"
    AUDIT_FAILED=1
fi

if [ "${AUDIT_FAILED}" -ne 0 ]; then
    echo "❌ BUILD FAILED AUDIT. Release distribution rejected."
    exit 1
fi

echo "=================================================================="
echo "🎉 RELEASE BUILD SUCCESSFUL & AUDITED"
echo "Artifact Directory: ${DIST_DIR}"
echo "=================================================================="


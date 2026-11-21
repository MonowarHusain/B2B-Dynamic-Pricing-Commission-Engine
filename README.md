# Hybrid Binary-Protected Release & Licensing Engine

A reference architecture and production template for distributing Python applications with protected proprietary business logic and asymmetric cryptographic license verification.

> 🌐 **Interactive Architecture Showcase & Live Sandbox:**  
> Explore the animated trust boundary, tamper sandbox, and live margin simulator at  
> 👉 **[https://monowarhusain.github.io/B2B-Dynamic-Pricing-Commission-Engine/](https://monowarhusain.github.io/B2B-Dynamic-Pricing-Commission-Engine/)**

---

## 1. Overview & Threat Model

When deploying specialized business software (such as dynamic pricing algorithms, commission schedules, and profit guardrails) into client-controlled environments, on-premise infrastructure, or edge servers, shipping plain Python source code exposes intellectual property to unauthorized inspection, modification, or license evasion.

This project demonstrates a **Hybrid Protected Release Architecture**:
1. **Readable Client Wrapper (`app_wrapper/`)**: Open FastAPI application layer with customizable endpoints, Jinja2/Tailwind UI, and hot-swappable license management.
2. **Native Core Engine (`core_engine/`)**: Sensitive calculation formulas, volume discount schedules, and margin floors compiled directly into native C-extension shared objects (`.so`/`.pyd`) via Cython.
3. **Ed25519 License Guard**: The vendor public key is hard-baked into native machine code during release assembly. License tokens (`license.key`) are signed offline with an Ed25519 private key, enforcing expiration timestamps, client tiers, and hostname hardware locks before allowing calculations.

---

## 2. Architecture Diagram

```
 CLIENT / CALLER ENVIRONMENT
 ─────────────────────────────────────────────────────────────────────────────
        │
        ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │ app_wrapper/ (Open / Customizable Layer)                                  │
 │                                                                           │
 │   • FastAPI Server (main.py)                                              │
 │   • HTML5 / Tailwind Dashboard (templates/index.html)                    │
 │   • Dynamic License Hot-Swap (POST /api/upload-license)                   │
 └─────────────────────────────────────┬─────────────────────────────────────┘
                                       │ imports
                                       ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │ dist/client_release/core_engine/ (Protected Native Binaries)              │
 │                                                                           │
 │   • license_guard.<platform>.so                                           │
 │       - Baked-in Ed25519 Public Key                                       │
 │       - Validates canonical sorted JSON data and Base64 signatures        │
 │       - Validates expiration epoch and socket.gethostname()               │
 │                                                                           │
 │   • pricing_engine.<platform>.so                                          │
 │       - Enforces active license verification on every calculation         │
 │       - Applies volume tiers (5%, 12%, 20%) capped by license tier        │
 │       - Applies regional taxation (BD: 15%, US: 8%, EU: 20%)             │
 │       - Computes sales representative commission slabs (4%, 6%, 8%)       │
 │       - Enforces hidden 18.0% minimum net profit margin floor             │
 │       - Returns SHA-256 integrity digest over calculation outputs         │
 │                                                                           │
 │   • __init__.py (0-byte package marker only; zero .py or .c sources)      │
 └───────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Directory Layout

```
.
├── Makefile                     # Developer automation commands
├── requirements.txt             # Pinned minimal dependencies
├── LICENSE                      # MIT License
├── README.md                    # System documentation
├── .secrets/                    # [GIT-IGNORED] Ed25519 private and public keys
├── core_engine/                 # Raw source engine (compiled during release build)
│   ├── __init__.py
│   ├── license_guard.py         # Signature & license validation module
│   └── pricing_engine.py        # Business logic, taxation, commissions & guardrails
├── app_wrapper/                 # Open client application layer
│   ├── main.py                  # FastAPI application and route handlers
│   ├── sample_orders.json       # Representative B2B order batch
│   └── templates/
│       └── index.html           # Tailwind CSS dashboard interface
├── scripts/
│   ├── keygen.py                # Generates Ed25519 keypair into .secrets/
│   ├── sign_license.py          # Signs license payloads with private key
│   └── build_release.sh         # Compiles core with Cython & audits dist/
├── tests/
│   ├── test_security_and_pricing.py  # Pytest regression suite
│   └── red_team_verification.py      # Standalone adversarial security suite
└── dist/                        # [GIT-IGNORED] Generated release distribution
    └── client_release/
        ├── requirements.txt
        ├── license.key          # 30-day host-bound token
        ├── app_wrapper/         # Readable wrapper and UI
        └── core_engine/         # Contains ONLY compiled .so/.pyd binaries
```

---

## 4. Quickstart Guide

### Prerequisites
- Python 3.9+
- A C compiler (`clang` on macOS, `gcc` on Linux)

### Step 1: Initialize Virtual Environment
```bash
make setup
```

### Step 2: Generate Asymmetric Signing Keys
```bash
make keygen
```
This creates `.secrets/private.pem` (mode `0600`) and `.secrets/public.pem` (mode `0644`). This folder is ignored by git and should remain strictly with the vendor.

### Step 3: Build Protected Release Artifact
```bash
make build
```
This runs `scripts/build_release.sh`, which:
- Injects `.secrets/public.pem` into `license_guard.py`.
- Compiles `core_engine/` using Cython into native machine code.
- Assembles the clean distribution in `dist/client_release/`.
- Issues a 30-day enterprise license tied to the current machine.
- Audits `dist/client_release/core_engine/` to ensure zero `.py` or `.c` files exist.

### Step 4: Run Tests
```bash
make test
```

### Step 5: Start Release Server
```bash
make run
```
Open your browser at `http://localhost:8000` to interact with the dashboard, load sample orders, upload licenses, and test pricing breakdowns.

---

## 5. Red-Team Verification Guide

Anyone evaluating or auditing this template can test the security guardrails:

### 1. Tamper Resistance Test
Decode `dist/client_release/license.key` from Base64, modify the `tier` to `"enterprise"` or extend `expires_at`, and re-encode. The core engine immediately raises:
`RuntimeError: License verification failed: Cryptographic signature mismatch!`

### 2. Expiration Lockout Test
Generate an expired license token:
```bash
python3 scripts/sign_license.py --client "Expired Corp" --days -1 --out dist/client_release/license.key
```
Calling the calculation API returns `HTTP 403 Forbidden` with:
`License verification failed: License expired on ...`

### 3. Host Mismatch Test
Generate a license locked to another hostname:
```bash
python3 scripts/sign_license.py --host "unauthorized-foreign-node" --out dist/client_release/license.key
```
Calling the calculation API is rejected with:
`License verification failed: Host mismatch! License is locked to 'unauthorized-foreign-node' ...`

### 4. Source Leak Verification
Run an inspection check inside `dist/client_release/core_engine/`:
```bash
find dist/client_release/core_engine/ -type f
```
Output will confirm only `.so` (or `.pyd`) compiled binaries and an empty `__init__.py` exist.

---

## 6. Security Boundaries & Recommendations

- **Binary Obfuscation vs. True Secrets**: Cython compiles Python into native C code and machine binaries, making casual inspection, string scraping, and automated decompilation significantly harder than raw `.pyc` files.
- **Critical Secrets**: For mission-critical IP or high-value cryptographic secrets, compute those parts behind a vendor-operated SaaS API rather than distributing them to client hardware.
- **Key Storage**: The private key (`.secrets/private.pem`) must NEVER be distributed in client releases. Only the public key is embedded in compiled binaries.


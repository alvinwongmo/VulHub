# Build the Windows onedir package

The public package does not require Python. Python and PyInstaller are only
required on the development computer that creates the release.

## Build

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
powershell -ExecutionPolicy Bypass -File .\packaging\build_onedir.ps1
```

The output is created at:

```text
release/
└─ VulHub-Windows-x64/
   ├─ VulHub.exe
   ├─ README.txt
   └─ _internal/
```

Users must keep the whole `VulHub-Windows-x64` directory and launch
`VulHub.exe`. They do not need Python, pip, CMD, or extra packages.

The first launch creates `vulhub.db` beside `VulHub.exe`. The database and any
saved API Key are intentionally excluded from source control and release ZIPs.

All directory and file names inside the release package use ASCII characters.
Upload `release/VulHub-Windows-x64.zip` and `release/SHA256SUMS.txt` as GitHub
Release assets instead of committing generated binaries to the source tree.

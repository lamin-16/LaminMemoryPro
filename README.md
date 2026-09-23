# LaminMemoryPro

Secure AI Memory & Context Management System

Author: lamin-16 | https://github.com/lamin-16/LaminMemoryPro
Version: 1.0.0 | AES-256-GCM + PBKDF2-SHA256

## Install (Termux)
pkg install python git -y && pip install cryptography
python lamin_memory.py init

## Commands
python lamin_memory.py add -t "Title" -c "Content" --tags "ai,work"
python lamin_memory.py list
python lamin_memory.py show <id>
python lamin_memory.py search "keyword"
python lamin_memory.py delete <id>
python lamin_memory.py ctx add myctx
python lamin_memory.py ctx list
python lamin_memory.py ctx show myctx
python lamin_memory.py export -o backup.json
python lamin_memory.py stats

## Vault Location: ~/.laminmemorypro/

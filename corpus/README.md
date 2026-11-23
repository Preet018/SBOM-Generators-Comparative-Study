# Corpus snapshot (frozen 22 Nov 2026)

These are frozen copies of the three subject projects used in the P16 study. **Do not edit files in this folder.** All study-specific Dockerfiles and variants live elsewhere in the repo and use these folders as their build context. The snapshot must keep matching what we report in the paper.

| Folder | Original project | Ecosystems |
|---|---|---|
| `bakery-inventory-management/` | Bakery Inventory Management System (Spring Boot backend + React/Vite frontend) | Java/Maven, Node.js/npm |
| `log-anomaly-detection/` | Log Anomaly Detection (Python microservices + MongoDB, Docker/K8s/Ansible/Jenkins) | Python/pip, OS (Debian, Ubuntu) |
| `multi-client-tcp-server/` | Multi-client TCP banking server | C (libc + pthread) |

## Files left out of the snapshot

These do not affect any SBOM, build or container image in the study:

| Removed | Why |
|---|---|
| `bakery-inventory-management/Database/` | SQL schema and dummy data. Not part of any build or image. |
| `bakery-inventory-management/dummy_images/` | Sample product photos (3.1 MB). Not part of any build or image. |
| `log-anomaly-detection/data_storage/KDD*.txt` | NSL-KDD training/test datasets (~40 MB). Not copied into any image: the `data_storage` Dockerfile only copies `init.js`. |
| `multi-client-tcp-server/class_diagram.pdf` | Documentation only. |

## Kept on purpose

- `multi-client-tcp-server/client` and `server`: prebuilt **Mach-O arm64 (macOS)** binaries committed to the original repo. Kept as a "foreign binary in source tree" case.
- `log-anomaly-detection/models/*.pkl`: copied into the prediction-service image by its Dockerfile, so needed to reproduce that image faithfully.
- Deployment configs (`Kubernetes/`, `Ansible/`, `Jenkinsfile`, `docker-compose.yml`): kept so the "source as committed" (S1) scans see the repository as it really is.

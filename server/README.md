# WauditBox v2.0 — Central Server

This directory contains the central server infrastructure code.

## Stack (Section 8.3 of spec)

| Component | Technology |
|-----------|-----------|
| VPN | WireGuard — pool 10.200.0.0/16 |
| API | FastAPI + Uvicorn + Redis Queue |
| Database | PostgreSQL |
| Monitoring | Prometheus + Grafana |
| Capacity | 1000+ gadgets |

## Deployment

```bash
# Server setup will be documented here
# Targeting: VPS with 8 vCPU / 32GB RAM

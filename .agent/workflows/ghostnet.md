---
description: Start, stop, monitor, and manage the GhostNet decentralized network
---

# GhostNet Infrastructure Operations

## Quick Start (One Command Boot)

// turbo-all

1. Start the full system using the orchestrator:
```
npm start
```
This runs the orchestrator which validates environment, installs deps, starts all services via PM2, and runs health checks.

## Start in Specific Modes

2. Cloud mode (server + bridge only):
```
npm run start:cloud
```

3. Local node mode (full mesh):
```
npm run start:local
```

4. Development mode (all services + verbose logging):
```
npm run start:dev
```

## PM2 Direct Management

5. Start all services directly via PM2:
```
pm2 start ecosystem.config.cjs
```

6. Start a single service:
```
pm2 start ecosystem.config.cjs --only ghostnet-server
```

7. Restart a specific service:
```
pm2 restart ghostnet-server
```

8. View live logs:
```
pm2 logs
```

9. View logs for a specific service:
```
pm2 logs ghostnet-bridge
```

## Health & Monitoring

10. Run a one-shot health check:
```
npm run check
```

11. Start the continuous watchdog monitor:
```
npm run watch
```

12. View service status:
```
npm run status
```

13. Check the detailed server health endpoint:
```
curl http://localhost:8080/status
```

14. Check inter-service communication:
```
curl http://localhost:8080/health/bridge
```

## Stopping Services

15. Stop all services:
```
npm run stop
```

16. Stop via PM2:
```
pm2 stop all
```

17. Delete all PM2 processes:
```
pm2 delete all
```

## Troubleshooting

18. If a service keeps crashing, check its error log:
```
Get-Content logs/ghostnet-server-error.log -Tail 50
```

19. If ports are blocked, find and kill the process:
```
netstat -ano | findstr :8080
```

20. Reinstall dependencies:
```
npm install
```

21. View the watchdog log:
```
Get-Content logs/watchdog.log -Tail 20
```

/**
 * Synthetic Sample Server Logs for Testing & Demonstration
 * Free of real credentials, private user data, or sensitive production information.
 */

export interface SampleLogDefinition {
  id: string;
  name: string;
  category: string;
  description: string;
  content: string;
}

export const SAMPLE_LOGS: SampleLogDefinition[] = [
  {
    id: 'ssh_brute_force',
    name: 'SSH Brute-Force & Credential Stuffing',
    category: 'Authentication Attacks',
    description: 'Simulates credential guessing across root, admin, test, and dev accounts, followed by an anomalous successful login.',
    content: `Oct 25 14:02:11 edge-bastion-01 sshd[28410]: Failed password for invalid user admin from 198.51.100.42 port 49212 ssh2
Oct 25 14:02:14 edge-bastion-01 sshd[28412]: Failed password for invalid user admin from 198.51.100.42 port 49214 ssh2
Oct 25 14:02:18 edge-bastion-01 sshd[28415]: Failed password for root from 198.51.100.42 port 49218 ssh2
Oct 25 14:02:22 edge-bastion-01 sshd[28418]: Failed password for invalid user test from 198.51.100.42 port 49222 ssh2
Oct 25 14:02:25 edge-bastion-01 sshd[28420]: Failed password for invalid user postgres from 198.51.100.42 port 49226 ssh2
Oct 25 14:02:29 edge-bastion-01 sshd[28423]: Failed password for invalid user deploy from 198.51.100.42 port 49230 ssh2
Oct 25 14:02:33 edge-bastion-01 sshd[28425]: Failed password for invalid user guest from 198.51.100.42 port 49234 ssh2
Oct 25 14:02:37 edge-bastion-01 sshd[28428]: Failed password for ubuntu from 198.51.100.42 port 49238 ssh2
Oct 25 14:02:40 edge-bastion-01 sshd[28430]: Failed password for ubuntu from 198.51.100.42 port 49242 ssh2
Oct 25 14:02:45 edge-bastion-01 sshd[28435]: Accepted password for ubuntu from 198.51.100.42 port 49248 ssh2
Oct 25 14:03:01 edge-bastion-01 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Oct 25 14:03:15 edge-bastion-01 sshd[28440]: Connection closed by 198.51.100.42 port 49248 [preauth]
Oct 25 14:05:02 edge-bastion-01 sshd[28501]: Failed password for invalid user oracle from 203.0.113.88 port 38102 ssh2
Oct 25 14:05:05 edge-bastion-01 sshd[28503]: Failed password for invalid user manager from 203.0.113.88 port 38104 ssh2
Oct 25 14:05:08 edge-bastion-01 sshd[28506]: Failed password for invalid user git from 203.0.113.88 port 38108 ssh2
Oct 25 14:05:12 edge-bastion-01 sshd[28510]: Failed password for invalid user ftpuser from 203.0.113.88 port 38112 ssh2
Oct 25 14:05:16 edge-bastion-01 sshd[28514]: Failed password for invalid user administrator from 203.0.113.88 port 38116 ssh2
Oct 25 14:06:00 edge-bastion-01 CRON[28550]: (root) CMD (/usr/local/bin/backup-sync.sh > /dev/null 2>&1)`
  },
  {
    id: 'nginx_web_attacks',
    name: 'Web Application Scanner & Probing',
    category: 'HTTP & Web Exploits',
    description: 'Automated web vulnerability reconnaissance, path traversal, sensitive configuration probes, and automated scanner signatures.',
    content: `198.51.100.15 - - [25/Oct/2026:14:10:01 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.15 - - [25/Oct/2026:14:10:04 +0000] "GET /robots.txt HTTP/1.1" 200 120 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.15 - - [25/Oct/2026:14:10:06 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.15 - - [25/Oct/2026:14:10:08 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.15 - - [25/Oct/2026:14:10:10 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.15 - - [25/Oct/2026:14:10:12 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 162 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.15 - - [25/Oct/2026:14:10:15 +0000] "GET /actuator/env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.15 - - [25/Oct/2026:14:10:18 +0000] "GET /api/v1/download?file=../../../../etc/passwd HTTP/1.1" 403 204 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.15 - - [25/Oct/2026:14:10:20 +0000] "GET /api/v1/query?id=1' OR '1'='1 HTTP/1.1" 500 523 "-" "sqlmap/1.7#stable"
198.51.100.15 - - [25/Oct/2026:14:10:22 +0000] "POST /api/v1/query HTTP/1.1" 500 523 "-" "sqlmap/1.7#stable"
198.51.100.15 - - [25/Oct/2026:14:10:25 +0000] "GET /swagger-ui.html HTTP/1.1" 404 162 "-" "sqlmap/1.7#stable"
203.0.113.50 - - [25/Oct/2026:14:11:02 +0000] "GET /api/v1/products HTTP/1.1" 200 3412 "https://shop.example.com" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
203.0.113.50 - - [25/Oct/2026:14:11:05 +0000] "GET /api/v1/cart HTTP/1.1" 200 1102 "https://shop.example.com" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
203.0.113.99 - - [25/Oct/2026:14:11:10 +0000] "GET /cgi-bin/test.cgi HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
203.0.113.99 - - [25/Oct/2026:14:11:12 +0000] "GET /shell.php HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
203.0.113.99 - - [25/Oct/2026:14:11:14 +0000] "GET /.aws/credentials HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
203.0.113.99 - - [25/Oct/2026:14:11:16 +0000] "GET /admin/config.php HTTP/1.1" 404 162 "-" "Nikto/2.1.6"`
  },
  {
    id: 'microservice_crash',
    name: 'Application Crash & DB Pool Exhaustion',
    category: 'Reliability & SRE',
    description: 'Python application crash sequence: PostgreSQL connection pool timeouts, cascading 500 errors, and memory pressure.',
    content: `2026-10-25 14:20:01,102 [INFO] [uvicorn.access] 10.0.4.12:44120 - "GET /api/health HTTP/1.1" 200
2026-10-25 14:20:05,214 [INFO] [app.orders] Order #84920 processed successfully in 42ms
2026-10-25 14:20:12,450 [WARN] [app.database] Database query latency high: 1420ms on table 'orders'
2026-10-25 14:20:15,810 [WARN] [app.database] Connection pool active connections: 98/100
2026-10-25 14:20:18,220 [ERROR] [app.database] ConnectionPoolTimeout: QueuePool limit of size 100 overflow 20 reached, connection timed out
2026-10-25 14:20:19,105 [ERROR] [app.orders] Failed to save order #84921: Database connection pool exhausted: timeout waiting for connection
2026-10-25 14:20:20,332 [ERROR] [uvicorn.access] 10.0.4.12:44132 - "POST /api/v1/orders HTTP/1.1" 500
2026-10-25 14:20:21,410 [ERROR] [uvicorn.access] 10.0.4.15:44136 - "POST /api/v1/orders HTTP/1.1" 500
2026-10-25 14:20:22,890 [ERROR] [uvicorn.access] 10.0.4.18:44140 - "POST /api/v1/orders HTTP/1.1" 500
2026-10-25 14:20:24,101 [CRITICAL] [app.core] Unhandled Exception: sqlalchemy.exc.OperationalError: could not connect to server: Connection refused
2026-10-25 14:20:25,050 [CRITICAL] [app.core] Worker process (PID 4120) died unexpectedly with status 1
2026-10-25 14:20:28,000 [WARN] [systemd] app-worker.service: Main process exited, code=exited, status=1/FAILURE
2026-10-25 14:20:29,100 [INFO] [systemd] app-worker.service: Scheduled restart job, restart counter is at 1.
2026-10-25 14:20:30,220 [INFO] [systemd] Started Application Worker Service.`
  },
  {
    id: 'syslog_system',
    name: 'Linux Syslog & Kernel OOM Incident',
    category: 'System & Infrastructure',
    description: 'System-level syslog with cron jobs, privilege escalation sudo calls, and kernel Out-of-Memory killer execution.',
    content: `Oct 25 14:15:01 app-node-03 CRON[12490]: (root) CMD (/usr/lib/x86_64-linux-gnu/sa/sa1 1 1)
Oct 25 14:15:22 app-node-03 sudo:   devops : TTY=pts/1 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/tail -n 100 /var/log/syslog
Oct 25 14:15:40 app-node-03 systemd[1]: Starting Daily apt upgrade and clean activities...
Oct 25 14:16:10 app-node-03 systemd[1]: apt-daily-upgrade.service: Deactivated successfully.
Oct 25 14:16:30 app-node-03 kernel: [ 4210.890] [warn] High memory pressure detected: 94% swap in use
Oct 25 14:16:35 app-node-03 kernel: [ 4215.112] Out of memory: Kill process 3912 (python3) score 892 or sacrifice child
Oct 25 14:16:35 app-node-03 kernel: [ 4215.114] Killed process 3912 (python3) total-vm:4194304kB, anon-rss:3670016kB, file-rss:0kB
Oct 25 14:16:40 app-node-03 systemd[1]: analytics-pipeline.service: Main process exited, code=killed, status=9/KILL
Oct 25 14:16:41 app-node-03 systemd[1]: analytics-pipeline.service: Failed with result 'oom-kill'.
Oct 25 14:17:00 app-node-03 CRON[12550]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))`
  },
  {
    id: 'json_cloudwatch',
    name: 'Cloud Native JSON Microservice Logs',
    category: 'JSON / CloudWatch',
    description: 'Structured JSON log streams showing API gateway 401 unauthenticated spikes and service timeout exceptions.',
    content: `{"timestamp":"2026-10-25T14:30:00Z","level":"INFO","service":"auth-service","msg":"Token generated for user: s_chen","ip":"192.168.1.50"}
{"timestamp":"2026-10-25T14:30:04Z","level":"WARN","service":"auth-service","msg":"Invalid HMAC signature in JWT header","ip":"198.51.100.77","path":"/auth/verify"}
{"timestamp":"2026-10-25T14:30:06Z","level":"WARN","service":"auth-service","msg":"Invalid HMAC signature in JWT header","ip":"198.51.100.77","path":"/auth/verify"}
{"timestamp":"2026-10-25T14:30:09Z","level":"WARN","service":"auth-service","msg":"Invalid HMAC signature in JWT header","ip":"198.51.100.77","path":"/auth/verify"}
{"timestamp":"2026-10-25T14:30:12Z","level":"ERROR","service":"auth-service","msg":"Authentication rate limit exceeded for client","ip":"198.51.100.77","status":429}
{"timestamp":"2026-10-25T14:30:20Z","level":"ERROR","service":"payment-gateway","msg":"Payment provider timeout after 5000ms","error":{"name":"TimeoutError","message":"ETIMEDOUT payment.external.net:443"}}
{"timestamp":"2026-10-25T14:30:22Z","level":"CRITICAL","service":"payment-gateway","msg":"Transaction failed: circuit breaker OPEN","status":503}`
  }
];

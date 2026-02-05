# Complete SDL → Manifest Examples

These are **golden reference examples** validated against the actual Akash provider code.

Each example shows the exact manifest JSON that must be generated from the SDL.

## Table of Contents

1. [Simple Service (nginx)](#1-simple-service-nginx)
2. [Comprehensive Multi-Service](#2-comprehensive-multi-service)
3. [GPU Deployment](#3-gpu-deployment)

---

## 1. Simple Service (nginx)

### Manifest Output

```json
[
  {
    "name": "westcoast",
    "services": [
      {
        "name": "web",
        "image": "nginx",
        "command": null,
        "args": null,
        "env": null,
        "resources": {
          "id": 1,
          "cpu": {
            "units": {
              "val": "100"
            }
          },
          "memory": {
            "size": {
              "val": "134217728"
            }
          },
          "storage": [
            {
              "name": "default",
              "size": {
                "val": "1073741824"
              }
            }
          ],
          "gpu": {
            "units": {
              "val": "0"
            }
          },
          "endpoints": []
        },
        "count": 2,
        "expose": [
          {
            "port": 80,
            "externalPort": 0,
            "proto": "TCP",
            "service": "",
            "global": true,
            "hosts": [
              "ahostname.com"
            ],
            "httpOptions": {
              "maxBodySize": 1048576,
              "readTimeout": 60000,
              "sendTimeout": 60000,
              "nextTries": 3,
              "nextTimeout": 0,
              "nextCases": [
                "error",
                "timeout"
              ]
            },
            "ip": "",
            "endpointSequenceNumber": 0
          },
          {
            "port": 12345,
            "externalPort": 0,
            "proto": "UDP",
            "service": "",
            "global": true,
            "hosts": null,
            "httpOptions": {
              "maxBodySize": 1048576,
              "readTimeout": 60000,
              "sendTimeout": 60000,
              "nextTries": 3,
              "nextTimeout": 0,
              "nextCases": [
                "error",
                "timeout"
              ]
            },
            "ip": "",
            "endpointSequenceNumber": 0
          }
        ],
        "credentials": null
      }
    ]
  }
]
```

### Key Observations

1. **Null fields**: `command`, `args`, `env`, `credentials` all `null` (NOT empty arrays)
2. **CPU units**: `"100"` (string, millicores)
3. **Memory size**: `"134217728"` (string, 128Mi in bytes)
4. **Storage size**: `"1073741824"` (string, 1Gi in bytes)
5. **GPU always present**: Even with 0 units
6. **httpOptions**: Present on BOTH TCP and UDP expose entries
7. **Hosts**: Array `["ahostname.com"]` for first expose, `null` for second
8. **externalPort**: `0` when not explicitly set

---

## 2. Comprehensive Multi-Service

Demonstrates command/args/env, multiple services, multiple storage volumes.

### Manifest Output (Condensed - showing key patterns)

```json
[
  {
    "name": "dcloud",
    "services": [
      {
        "name": "api",
        "image": "node:20-alpine",
        "command": [
          "node"
        ],
        "args": [
          "server.js",
          "--port=3000"
        ],
        "env": [
          "NODE_ENV=production",
          "DATABASE_URL=postgres://user:pass@db:5432/mydb",
          "REDIS_URL=redis://cache:6379",
          "LOG_LEVEL=info"
        ],
        "resources": {
          "id": 1,
          "cpu": {
            "units": {
              "val": "2000"
            }
          },
          "memory": {
            "size": {
              "val": "2147483648"
            }
          },
          "storage": [
            {
              "name": "default",
              "size": {
                "val": "5368709120"
              }
            },
            {
              "name": "uploads",
              "size": {
                "val": "10737418240"
              }
            }
          ],
          "gpu": {
            "units": {
              "val": "0"
            }
          },
          "endpoints": []
        },
        "count": 3,
        "expose": [
          {
            "port": 3000,
            "externalPort": 3000,
            "proto": "TCP",
            "service": "",
            "global": true,
            "hosts": null,
            "httpOptions": {
              "maxBodySize": 1048576,
              "readTimeout": 60000,
              "sendTimeout": 60000,
              "nextTries": 3,
              "nextTimeout": 0,
              "nextCases": [
                "error",
                "timeout"
              ]
            },
            "ip": "",
            "endpointSequenceNumber": 0
          }
        ],
        "credentials": null
      },
      {
        "name": "cache",
        "image": "redis:7.2",
        "command": null,
        "args": null,
        "env": null,
        "resources": {
          "id": 1,
          "cpu": {
            "units": {
              "val": "250"
            }
          },
          "memory": {
            "size": {
              "val": "1073741824"
            }
          },
          "storage": [
            {
              "name": "default",
              "size": {
                "val": "536870912"
              }
            }
          ],
          "gpu": {
            "units": {
              "val": "0"
            }
          },
          "endpoints": []
        },
        "count": 1,
        "expose": [
          {
            "port": 6379,
            "externalPort": 0,
            "proto": "TCP",
            "service": "",
            "global": false,
            "hosts": null,
            "httpOptions": {
              "maxBodySize": 1048576,
              "readTimeout": 60000,
              "sendTimeout": 60000,
              "nextTries": 3,
              "nextTimeout": 0,
              "nextCases": [
                "error",
                "timeout"
              ]
            },
            "ip": "",
            "endpointSequenceNumber": 0
          }
        ],
        "credentials": null
      },
      {
        "name": "db",
        "image": "postgres:16",
        "command": null,
        "args": null,
        "env": [
          "POSTGRES_DB=mydb",
          "POSTGRES_USER=user",
          "POSTGRES_PASSWORD=pass"
        ],
        "resources": {
          "id": 1,
          "cpu": {
            "units": {
              "val": "1000"
            }
          },
          "memory": {
            "size": {
              "val": "4294967296"
            }
          },
          "storage": [
            {
              "name": "default",
              "size": {
                "val": "21474836480"
              }
            }
          ],
          "gpu": {
            "units": {
              "val": "0"
            }
          },
          "endpoints": []
        },
        "count": 1,
        "expose": [
          {
            "port": 5432,
            "externalPort": 0,
            "proto": "TCP",
            "service": "",
            "global": false,
            "hosts": null,
            "httpOptions": {
              "maxBodySize": 1048576,
              "readTimeout": 60000,
              "sendTimeout": 60000,
              "nextTries": 3,
              "nextTimeout": 0,
              "nextCases": [
                "error",
                "timeout"
              ]
            },
            "ip": "",
            "endpointSequenceNumber": 0
          }
        ],
        "credentials": null
      },
      {
        "name": "web",
        "image": "nginx:1.25.3",
        "command": [
          "nginx",
          "-g",
          "daemon off;"
        ],
        "args": [
          "--prefix=/usr/share/nginx"
        ],
        "env": [
          "NGINX_HOST=example.com",
          "NGINX_PORT=80"
        ],
        "resources": {
          "id": 1,
          "cpu": {
            "units": {
              "val": "500"
            }
          },
          "memory": {
            "size": {
              "val": "536870912"
            }
          },
          "storage": [
            {
              "name": "default",
              "size": {
                "val": "2147483648"
              }
            }
          ],
          "gpu": {
            "units": {
              "val": "0"
            }
          },
          "endpoints": []
        },
        "count": 2,
        "expose": [
          {
            "port": 80,
            "externalPort": 80,
            "proto": "TCP",
            "service": "",
            "global": true,
            "hosts": [
              "web.example.com",
              "www.example.com"
            ],
            "httpOptions": {
              "maxBodySize": 1048576,
              "readTimeout": 60000,
              "sendTimeout": 60000,
              "nextTries": 3,
              "nextTimeout": 0,
              "nextCases": [
                "error",
                "timeout"
              ]
            },
            "ip": "",
            "endpointSequenceNumber": 0
          },
          {
            "port": 443,
            "externalPort": 443,
            "proto": "TCP",
            "service": "",
            "global": true,
            "hosts": null,
            "httpOptions": {
              "maxBodySize": 1048576,
              "readTimeout": 60000,
              "sendTimeout": 60000,
              "nextTries": 3,
              "nextTimeout": 0,
              "nextCases": [
                "error",
                "timeout"
              ]
            },
            "ip": "",
            "endpointSequenceNumber": 0
          },
          {
            "port": 8080,
            "externalPort": 0,
            "proto": "TCP",
            "service": "",
            "global": false,
            "hosts": null,
            "httpOptions": {
              "maxBodySize": 1048576,
              "readTimeout": 60000,
              "sendTimeout": 60000,
              "nextTries": 3,
              "nextTimeout": 0,
              "nextCases": [
                "error",
                "timeout"
              ]
            },
            "ip": "",
            "endpointSequenceNumber": 0
          }
        ],
        "credentials": null
      }
    ]
  }
]
```

### Key Observations

1. **Service ordering**: Alphabetical - `api`, `cache`, `db`, `web`
2. **Command/args present**: Non-null arrays when specified
3. **Env format**: Array of `"KEY=VALUE"` strings
4. **Multiple storage**: Each with unique name and size
5. **Global vs non-global**: `cache` and `db` use `global: false` for internal services
6. **Multiple hosts**: Array with multiple hostnames
7. **externalPort**: Can be non-zero (3000, 80, 443)

---

## 3. GPU Deployment

Demonstrates GPU attributes, storage attributes, and storage params (volume mounts).

### Manifest Output

```json
[
  {
    "name": "dcloud",
    "services": [
      {
        "name": "sglang",
        "image": "lmsysorg/sglang:dev-cu13",
        "command": [
          "bash",
          "-c"
        ],
        "args": [
          "python3 -m sglang.launch_server --model-path Qwen/Qwen3-VL-Embedding-8B --tensor-parallel-size 2 --host 0.0.0.0 --port 8000 --is-embedding --trust-remote-code --mem-fraction-static 0.87"
        ],
        "env": null,
        "resources": {
          "id": 1,
          "cpu": {
            "units": {
              "val": "32000"
            }
          },
          "memory": {
            "size": {
              "val": "68719476736"
            }
          },
          "storage": [
            {
              "name": "default",
              "size": {
                "val": "53687091200"
              }
            },
            {
              "name": "data",
              "size": {
                "val": "322122547200"
              },
              "attributes": [
                {
                  "key": "class",
                  "value": "beta3"
                },
                {
                  "key": "persistent",
                  "value": "true"
                }
              ]
            },
            {
              "name": "shm",
              "size": {
                "val": "10737418240"
              },
              "attributes": [
                {
                  "key": "class",
                  "value": "ram"
                },
                {
                  "key": "persistent",
                  "value": "false"
                }
              ]
            }
          ],
          "gpu": {
            "units": {
              "val": "2"
            },
            "attributes": [
              {
                "key": "vendor/nvidia/model/h100/ram/80Gi",
                "value": "true"
              },
              {
                "key": "vendor/nvidia/model/a100/ram/40Gi",
                "value": "true"
              }
            ]
          },
          "endpoints": []
        },
        "count": 1,
        "expose": [
          {
            "port": 8000,
            "externalPort": 8000,
            "proto": "TCP",
            "service": "",
            "global": true,
            "hosts": null,
            "httpOptions": {
              "maxBodySize": 1048576,
              "readTimeout": 60000,
              "sendTimeout": 60000,
              "nextTries": 3,
              "nextTimeout": 0,
              "nextCases": [
                "error",
                "timeout"
              ]
            },
            "ip": "",
            "endpointSequenceNumber": 0
          }
        ],
        "params": {
          "storage": [
            {
              "name": "shm",
              "mount": "/dev/shm",
              "readOnly": false
            },
            {
              "name": "data",
              "mount": "/root/.cache",
              "readOnly": false
            }
          ]
        },
        "credentials": null
      }
    ]
  }
]
```

### Key Observations

1. **GPU units**: `"2"` (string)
2. **GPU attributes**: Composite keys in format `vendor/nvidia/model/h100/ram/80Gi`
3. **Multiple GPU models**: Provider tries in order (h100 first, then a100)
4. **Storage attributes**: Sorted alphabetically by key (`class` before `persistent`)
5. **Storage params**: Maps storage names to mount points
6. **readOnly field**: camelCase, lowercase 'O'
7. **Large numbers**: CPU `"32000"` (32 cores = 32000 millicores), memory `"68719476736"` (64Gi)

---

## Edge Cases and Special Rules

### 1. Empty vs Null Hosts

```json
// No hosts specified
{
  "hosts": null
}

// Hosts specified (even if array becomes empty after filtering)
{
  "hosts": ["example.com"]
}
```

### 2. Environment Variables Format

```json
// Correct
{
  "env": [
    "KEY1=value1",
    "KEY2=value2"
  ]
}

// Wrong - not supported
{
  "env": {
    "KEY1": "value1",
    "KEY2": "value2"
  }
}
```

### 3. Service Count Default

If not specified in SDL deployment section, default to `1`.

### 4. External Port Zero

When SDL doesn't specify `as:` for expose, use `externalPort: 0`.

### 5. Protocol Case

Always uppercase: `"TCP"`, `"UDP"` (not `"tcp"` or `"Tcp"`).

### 6. Storage Attribute Values

Both boolean and string values are valid:

- `"persistent": "true"` (string)
- `"persistent": true` (boolean - serializes to `"true"`)

Always serialize as string in JSON output.

### 7. Memory/Storage Field Name

Use `"size"` (Go JSON field), NOT `"quantity"` (proto field).

```json
// Correct
{
  "memory": {
    "size": {"val": "536870912"}
  }
}

// Wrong
{
  "memory": {
    "quantity": {"val": "536870912"}
  }
}
```

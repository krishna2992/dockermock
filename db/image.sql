CREATE TABLE images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tag TEXT NOT NULL,
    json_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, tag)
);


INSERT INTO images (name, tag, json_data) VALUES(
    'alpine-python',
    '3.10',
    '{
    "env":{},
    "PATH":[
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin"
    ],
    "entrypoint": "/app/entrypoint.sh",
    "command": [
        "python"
    ],
    "volumes": {},
    "workingDir": "/"
}'
)

INSERT INTO images (name, tag, json_data) VALUES(
    'redis',
    '8.2.3',
    '{
    "env":{},
    "PATH":[
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin"
    ],
    "entrypoint": "/entrypoint.sh",
    "command": null,
    "volumes": {},
    "workingDir": "/var/db/redis"
}'
)


INSERT INTO images (name, tag, json_data) VALUES(
    'freebsd',
    '14.1',
    '{
    "env":{},
    "PATH":[
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin"
    ],
    "entrypoint": null,
    "command": ["tail", "-f", "/dev/null"],
    "volumes": {},
    "workingDir": "/root"
}'
)
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
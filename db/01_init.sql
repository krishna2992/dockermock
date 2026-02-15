-- ========================================
-- Container Image Registry Database Schema
-- ========================================

-- Drop existing tables if needed (optional safety)
DROP TABLE IF EXISTS Image_versions;
DROP TABLE IF EXISTS Images;

-- ----------------------------
-- 1. Images Table
-- ----------------------------
CREATE TABLE Images (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,   -- e.g., 'freebsd', 'myapp'
    description TEXT,
    latest_version_id INT,               -- FK to image_versions.id
    created_at TIMESTAMP DEFAULT NOW()
);

-- ----------------------------
-- 2. Image Versions Table
-- ----------------------------
CREATE TABLE Image_versions (
    id SERIAL PRIMARY KEY,
    image_id INT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    tag VARCHAR(100) NOT NULL,           -- e.g., '12', '13', 'v1.0.0'
    metadata JSONB,                      -- e.g., env, arch, os, labels
    digest VARCHAR(256),                 -- Optional content hash
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(image_id, tag)                -- Enforce unique tag per image
);

-- ----------------------------
-- 3. Add Foreign Key from images.latest_version_id → image_versions.id
-- ----------------------------
ALTER TABLE images
ADD CONSTRAINT fk_latest_version
FOREIGN KEY (latest_version_id)
REFERENCES image_versions(id)
ON DELETE SET NULL;

-- ----------------------------
-- Optional: Indexes
-- ----------------------------
CREATE INDEX idx_image_versions_image_id ON image_versions(image_id);
CREATE INDEX idx_image_versions_tag ON image_versions(tag);


-- ========================================
-- Container Database Schema
-- ========================================

CREATE TABLE containers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,                        -- Container name (hostname)
    image_id INTEGER REFERENCES images(id) ON DELETE SET NULL,
    status TEXT CHECK (status IN ('created', 'running', 'stopped', 'paused', 'exited')) 
           DEFAULT 'created',
    pid INTEGER DEFAULT -1,                                      -- PID of running process (if applicable)
    config_json TEXT,                                 -- Full OCI config JSON blob
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    exited_at TIMESTAMP,
    exit_code INTEGER, 
    project TEXT, 
    service TEXT
);



CREATE TABLE IF NOT EXISTS allocated_subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet TEXT NOT NULL,
    prefix INTEGER NOT NULL,
    UNIQUE(subnet, prefix)
);

-- Networks
CREATE TABLE networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL,
    driver VARCHAR(100) DEFAULT 'bridge', -- bridge, host, overlay, macvlan, none
    subnet VARCHAR(32),
    prefix INTEGER,
    labels TEXT DEFAULT '{}',
    created_at TIMESTAMP  DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name)
);


-- VOLUMES --
CREATE TABLE volumes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,                        -- Volume name (must be unique)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,   -- When the volume was created
    driver TEXT DEFAULT 'local',                      -- Volume driver (e.g., local)
    path TEXT NOT NULL,                               -- Host path where the volume is mounted/stored
    labels TEXT,                                      -- Optional metadata (stored as JSON string)
    options TEXT                                      -- Driver-specific config (stored as JSON string)
);


-- container-networks 
CREATE TABLE container_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL,
    container_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    UNIQUE(network_id, container_id),                   -- prevent duplicate entries
    FOREIGN KEY (network_id) REFERENCES networks(id),
    FOREIGN KEY (container_id) REFERENCES containers(id)
);

-- Volume-Containers
CREATE TABLE volume_containers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    volume_id INTEGER NOT NULL,
    container_id INTEGER NOT NULL,
    UNIQUE(volume_id, container_id),                   -- prevent duplicate entries
    FOREIGN KEY (volume_id) REFERENCES volumes(id),
    FOREIGN KEY (container_id) REFERENCES containers(id)
);
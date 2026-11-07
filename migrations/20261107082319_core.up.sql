-- ==========================================================
-- items
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    items (
        id UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        uom_base UUID NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
    );

-- ==========================================================
-- customers
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    customers (
        if UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        tax_code VARCHAR(255),
        address VARCHAR(255),
        phone_number VARCHAR(255),
        gmail VARCHAR(255),
        note TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
    );

-- ==========================================================
-- suppliers
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    suppliers (
        if UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        tax_code VARCHAR(255),
        address VARCHAR(255),
        phone_number VARCHAR(255),
        gmail VARCHAR(255),
        note TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
    );

-- ==========================================================
-- warehouses
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    warehouses (
        if UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        address VARCHAR(255),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
    );

CREATE TABLE IF NOT EXISTS
    warehouse_zones (
        if UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        zone_type VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
    );

CREATE TABLE IF NOT EXISTS
    warehouse_bins (
        if UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
    );

-- ==========================================================
-- boms
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    boms (
        if UUID NOT NULL DEFAULT uuidv7 (),
        uom_base UUID NOT NULL,
        qnt DECIMAL(9, 5),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
    );

CREATE TABLE IF NOT EXISTS
    bom_items (
        id UUID NOT NULL DEFAULT uuidv7 (),
        item_id UUID NOT NULL,
        uom UUID NOT NULL,
        qnt DECEM NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
    );

-- ==========================================================
-- uoms
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    uoms (
        if UUID NOT NULL DEFAULT uuidv7 (),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
    );
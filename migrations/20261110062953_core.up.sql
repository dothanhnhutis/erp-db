-- ==========================================================
-- Item master
-- ==========================================================
CREATE TYPE item_type AS ENUM(
    'RAW_MATERIAL',
    'PACKAGING',
    'FINISHED_GOOD',
    'SEMI_FINISHED',
    'SOLVENT'
);

CREATE TABLE
    items (
        id UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(40) NOT NULL UNIQUE, -- mã item
        name VARCHAR(255) NOT NULL,
        alias VARCHAR(255),
        item_type item_type NOT NULL, -- quyết định zone lưu & yêu cầu QC
        base_uom_id UUID NOT NULL, -- ĐƠN VỊ CHÍNH để lưu kho (thường là kg)
        is_lot_managed BOOLEAN NOT NULL DEFAULT TRUE, -- mỹ phẩm: bắt buộc theo lô
        requires_qc BOOLEAN NOT NULL DEFAULT TRUE, -- bắt buộc kiểm nhập (IQC) trước khi nhập kho
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_items PRIMARY KEY (id)
    );

CREATE INDEX idx_item_type ON items (item_type);

CREATE TYPE uom_dimension AS ENUM('MASS', 'VOLUME', 'COUNT', 'LENGTH', 'PACK');

CREATE TABLE
    uoms (
        id UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(20) NOT NULL UNIQUE,
        name VARCHAR(100) NOT NULL,
        dimension uom_dimension NOT NULL DEFAULT 'COUNT',
        ratio_to_anchor NUMERIC(18, 6), -- giá trị theo 1 đơn vị mốc của dimension (PACK = NULL)
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_uoms PRIMARY KEY (id),
        CONSTRAINT chk_dimension_type CHECK (
            dimension = 'PACK'
            OR ratio_to_anchor > 0
        ) -- đơn vị chuẩn bắt buộc có ratio dương
    );

CREATE TABLE
    item_uom_conversions (
        item_id UUID NOT NULL,
        uom_id UUID NOT NULL, -- đơn vị thay thế (vd thùng)
        factor_to_base NUMERIC(18, 6) NOT NULL CHECK (factor_to_base > 0), -- 1 uom = factor_to_base × base_uom
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT now(),
        CONSTRAINT pk_item_uom_conversion PRIMARY KEY (item_id, uom_id)
    );

-- =============================================================================
-- Vendors / Nhà cung cấp
-- =============================================================================
CREATE TABLE IF NOT EXISTS
    vendors (
        id UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        alias VARCHAR(255),
        tax_code VARCHAR(50),
        address VARCHAR(255),
        phone VARCHAR(50),
        email VARCHAR(255),
        notes TEXT,
        deleted_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_vendors PRIMARY KEY (id),
        CONSTRAINT uq_vendors_code UNIQUE (code)
    );

CREATE TABLE IF NOT EXISTS
    vendor_items (
        vendor_id UUID NOT NULL,
        item_id UUID NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_vendor_items PRIMARY KEY (vendor_id, item_id)
    );

CREATE INDEX idx_vendor_items_item ON vendor_items (item_id);

-- ==========================================================
-- BỘ ĐẾM SỐ CHỨNG TỪ (DOCUMENT NUMBER COUNTERS)
-- ==========================================================
-- Đếm sequence theo (loại chứng từ, tháng) để sinh po_number/gr_number reset mỗi tháng.
-- Bảng kỹ thuật: không updated_at, không soft-delete, được loại trừ khỏi audit log.
CREATE TABLE IF NOT EXISTS
    document_number_counters (
        doc_type VARCHAR(10) NOT NULL, -- 'PO' | 'GR' | (mở rộng sau)
        period VARCHAR(6) NOT NULL, -- 'YYMM' vd '2601'
        last_seq INT NOT NULL DEFAULT 0,
        CONSTRAINT pk_document_number_counters PRIMARY KEY (doc_type, period)
    );

-- -----------------------------------------------------------------------------
-- KHO 3 CẤP: locations -> warehouse_zones -> storage_bins
-- -----------------------------------------------------------------------------
CREATE TABLE
    locations (
        id UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(20) NOT NULL UNIQUE,
        name VARCHAR(150) NOT NULL,
        address TEXT,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_locations PRIMARY KEY (id)
    );

CREATE TYPE zone_type AS ENUM(
    'RAW_MATERIAL',
    'PACKAGING',
    'FINISHED_GOODS',
    'SOLVENT'
);

CREATE TABLE
    warehouse_zones (
        id UUID NOT NULL DEFAULT uuidv7 (),
        location_id UUID NOT NULL,
        code VARCHAR(20) NOT NULL,
        name VARCHAR(150) NOT NULL,
        zone_type zone_type NOT NULL, -- RAW_MATERIAL/PACKAGING/FINISHED_GOODS/SOLVENT
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_warehouse_zones PRIMARY KEY (id),
        CONSTRAINT uq_warehouse_zones_location_id_code UNIQUE (location_id, code)
    );

CREATE INDEX idx_zone_location ON warehouse_zones (location_id);

CREATE TYPE bin_type AS ENUM(
    'TEMPORARY',
    'PRESERVATION',
    'DISPOSAL',
    'RETURNS'
);

-- Tạm trữ/Bảo quản/Loại bỏ/Hàng trả về
CREATE TABLE
    storage_bins (
        id UUID NOT NULL DEFAULT uuidv7 (),
        zone_id UUID NOT NULL,
        code VARCHAR(20) NOT NULL,
        name VARCHAR(150) NOT NULL,
        bin_type bin_type NOT NULL, -- TEMPORARY/PRESERVATION/DISPOSAL/RETURNS
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_storage_bins PRIMARY KEY (id),
        CONSTRAINT uq_storage_bins_zone_id_code UNIQUE (zone_id, code)
    );

CREATE INDEX idx_bin_zone ON storage_bins (zone_id);
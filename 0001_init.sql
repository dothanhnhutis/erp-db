-- ==========================================================
-- Extension
-- ==========================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- cho EXCLUDE trên (uuid WITH =, daterange WITH &&) — hiệu lực công thức theo thời gian
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- ==========================================================
-- Config
-- ==========================================================
ALTER DATABASE pgdb
SET
    datestyle = 'ISO, DMY';

ALTER DATABASE pgdb
SET
    timezone = 'Asia/Ho_Chi_Minh';

-- ==========================================================
-- Log
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    audit_logs (
        id UUID NOT NULL DEFAULT uuidv7 (), -- Dùng kiểu UUID thực thụ
        table_name VARCHAR(100) NOT NULL,
        record_id TEXT NOT NULL,
        action VARCHAR(10) NOT NULL, -- INSERT, UPDATE, DELETE
        old_data JSONB,
        new_data JSONB,
        changed_by TEXT NOT NULL,
        transaction_id TEXT,
        changed_at TIMESTAMPTZ (3) DEFAULT NOW() NOT NULL,
        CONSTRAINT pk_audit_logs PRIMARY KEY (id, changed_at) -- Phải bao gồm cột phân mảnh
    )
PARTITION BY
    RANGE (changed_at);

CREATE INDEX IF NOT EXISTS idx_audit_logs_table_record ON audit_logs (table_name, record_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tx ON audit_logs (transaction_id);

-- Lưới an toàn: KHÔNG có partition nào thì mọi INSERT vào audit_logs đều fail, mà mọi
-- bảng đều có trigger audit -> toàn hệ thống không ghi được. Default hứng mọi khoảng
-- ngày chưa có partition; pg_partman (0002) sẽ tự chuyển dữ liệu ra partition đúng.
CREATE TABLE IF NOT EXISTS
    audit_logs_default PARTITION OF audit_logs DEFAULT;

-- ==========================================================
-- User & Role
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    users (
        id UUID NOT NULL DEFAULT uuidv7 (),
        email VARCHAR(255) NOT NULL,
        password_hash TEXT,
        username VARCHAR(100),
        status VARCHAR(20) NOT NULL DEFAULT 'PENDING_PASSWORD', -- ACTIVE | DEACTIVATED | PENDING_PASSWORD
        deactivated_at TIMESTAMPTZ (3), -- vô hiệu hoá lúc nào
        deleted_at TIMESTAMPTZ (3), -- xoá mềm
        password_changed_at TIMESTAMPTZ (3), -- lần cuối đổi mật khẩu
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_users PRIMARY KEY (id),
        CONSTRAINT chk_users_pending_password CHECK (
            status = 'PENDING_PASSWORD'
            OR password_hash IS NOT NULL
        ),
        CONSTRAINT chk_users_status CHECK (
            status IN ('ACTIVE', 'DEACTIVATED', 'PENDING_PASSWORD')
        )
    );

CREATE UNIQUE INDEX IF NOT EXISTS uidx_users_email ON users (email)
WHERE
    deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_users_status ON users (status)
WHERE
    deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS
    roles (
        id UUID NOT NULL DEFAULT uuidv7 (),
        name VARCHAR(255) NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE | DEACTIVATED
        deactivated_at TIMESTAMPTZ (3), -- vô hiệu hoá lúc nào
        deleted_at TIMESTAMPTZ (3), -- xoá mềm
        can_delete BOOLEAN NOT NULL DEFAULT TRUE,
        can_update BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_roles PRIMARY KEY (id),
        CONSTRAINT chk_roles_status CHECK (status IN ('ACTIVE', 'DEACTIVATED'))
    );

CREATE INDEX IF NOT EXISTS idx_roles_status ON roles (status)
WHERE
    deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uidx_roles_name_active ON roles (name)
WHERE
    deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS
    permissions (
        id UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(100) NOT NULL UNIQUE, -- vd: CHEMICAL_CREATE, PO_VIEW
        description TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_permissions PRIMARY KEY (id)
    );

CREATE TABLE IF NOT EXISTS
    role_permissions (
        role_id UUID NOT NULL,
        permission_id UUID NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_role_permissions PRIMARY KEY (role_id, permission_id)
    );

CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions (permission_id);

CREATE TABLE IF NOT EXISTS
    user_roles (
        user_id UUID NOT NULL,
        role_id UUID NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_id)
    );

CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles (role_id);

-- ==========================================================
-- User password & session
-- ==========================================================
CREATE TABLE
    user_sessions (
        id UUID NOT NULL DEFAULT uuidv7 (),
        user_id UUID NOT NULL,
        token_hash CHAR(64) NOT NULL UNIQUE,
        device_id VARCHAR(255), -- Fingerprint do client tự tạo, dùng để nhận ra "cùng máy" dù đổi IP
        device_name VARCHAR(255), -- Human-readable: "Chrome 124 · Windows 11", "MyApp 2.1 · macOS 14"
        device_type VARCHAR(20) NOT NULL, -- 'web' | 'desktop' | 'mobile'
        platform VARCHAR(100), -- "Windows 11" | "macOS 14.5" | "Ubuntu 22.04"
        app_version VARCHAR(50), -- Chỉ có trên desktop app, null với web
        user_agent TEXT, -- Raw User-Agent header, dùng để debug
        ip_address INET, -- IP lúc login, dùng để hiển thị "đăng nhập từ đâu"
        revoked_at TIMESTAMPTZ (3),
        revoke_reason VARCHAR(20),
        -- 'LOGOUT'  : user tự logout
        -- 'FORCED'  : user logout tất cả thiết bị
        -- 'USER'   : user thu hồi
        -- 'EXPIRED' : cleanup job đánh dấu sau khi hết hạn
        expires_at TIMESTAMPTZ (3) NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ (3), -- hoạt động gần nhất (cập nhật mỗi request; xem ghi chú audit B1)
        CONSTRAINT chk_revoke_reason CHECK (
            revoke_reason IN ('LOGOUT', 'FORCED', 'USER', 'EXPIRED')
        ),
        CONSTRAINT chk_user_sessions_device_type CHECK (device_type IN ('web', 'desktop', 'mobile')),
        CONSTRAINT pk_user_sessions PRIMARY KEY (id)
    );

CREATE INDEX idx_user_revoked ON user_sessions (user_id, revoked_at);

-- liệt kê nhanh phiên đang hoạt động + hỗ trợ "đăng xuất mọi thiết bị khác"
CREATE INDEX idx_user_sessions_active ON user_sessions (user_id, expires_at)
WHERE
    revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS
    password_tokens (
        id UUID NOT NULL DEFAULT uuidv7 (),
        user_id UUID NOT NULL,
        token_hash TEXT NOT NULL,
        type VARCHAR(20) NOT NULL, -- INIT | RESET_PASSWORD
        expires_at TIMESTAMPTZ (3) NOT NULL,
        used_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_password_tokens PRIMARY KEY (id),
        CONSTRAINT uq_password_tokens_token_hash UNIQUE (token_hash),
        CONSTRAINT chk_password_tokens_type CHECK (
            type IN ('INIT', 'RESET_PASSWORD')
        )
    );

CREATE INDEX idx_password_tokens_user_id ON password_tokens (user_id);

CREATE INDEX idx_password_tokens_expires_at ON password_tokens (expires_at);

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
        item_type item_type NOT NULL, -- quyết định zone lưu & yêu cầu QC
        base_uom_id UUID NOT NULL, -- ĐƠN VỊ CHÍNH để lưu kho (thường là kg)
        is_lot_managed BOOLEAN NOT NULL DEFAULT TRUE, -- mỹ phẩm: bắt buộc theo lô
        requires_qc BOOLEAN NOT NULL DEFAULT TRUE, -- bắt buộc kiểm nhập (IQC) trước khi nhập kho
        shelf_life_days INTEGER, -- hạn dùng mặc định (ngày)
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

-- =============================================================================
-- Purchase Order / Phiếu mua hàng
-- =============================================================================
CREATE TABLE IF NOT EXISTS
    purchase_orders (
        id UUID NOT NULL DEFAULT uuidv7 (),
        po_number VARCHAR(50) NOT NULL,
        vendor_id UUID NOT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'DRAFT', -- DRAFT | CONFIRMED | PARTIALLY_RECEIVED | RECEIVED | CANCELLED
        order_date DATE NOT NULL,
        expected_delivery_date DATE,
        currency VARCHAR(3) NOT NULL DEFAULT 'VND', -- VND | USD
        exchange_rate DECIMAL(15, 6) NOT NULL DEFAULT 1, -- 1 currency = exchange_rate VND
        subtotal DECIMAL(15, 2) NOT NULL DEFAULT 0, -- = SUM(line_amount), theo currency (auto sync bởi trigger)
        shipping_fee DECIMAL(15, 2) NOT NULL DEFAULT 0, -- phí vận chuyển, theo currency
        tax_amount DECIMAL(15, 2) NOT NULL DEFAULT 0, -- = SUM(line_vat_amount), theo currency (auto sync bởi trigger)
        discount_amount DECIMAL(15, 2) NOT NULL DEFAULT 0, -- chiết khấu, theo currency
        -- Tổng tiền = subtotal + phí + thuế − chiết khấu. Cả 2 generated chỉ tham chiếu cột thường (PG không cho generated tham chiếu generated)
        total_amount DECIMAL(15, 2) GENERATED ALWAYS AS (
            subtotal + shipping_fee + tax_amount - discount_amount
        ) STORED,
        total_amount_vnd DECIMAL(15, 2) GENERATED ALWAYS AS (
            (
                subtotal + shipping_fee + tax_amount - discount_amount
            ) * exchange_rate
        ) STORED,
        created_by UUID NOT NULL,
        notes TEXT,
        deleted_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_purchase_orders PRIMARY KEY (id),
        CONSTRAINT uq_purchase_orders_no UNIQUE (po_number),
        CONSTRAINT chk_purchase_orders_status CHECK (
            status IN (
                'DRAFT',
                'CONFIRMED',
                'PARTIALLY_RECEIVED',
                'RECEIVED',
                'CANCELLED'
            )
        ),
        CONSTRAINT chk_purchase_orders_currency CHECK (currency IN ('VND', 'USD')),
        CONSTRAINT chk_purchase_orders_exchange_rate CHECK (exchange_rate > 0),
        CONSTRAINT chk_purchase_orders_vnd_rate CHECK (
            currency <> 'VND'
            OR exchange_rate = 1
        ),
        CONSTRAINT chk_purchase_orders_amounts CHECK (
            subtotal >= 0
            AND shipping_fee >= 0
            AND tax_amount >= 0
            AND discount_amount >= 0
        )
    );

CREATE INDEX idx_purchase_orders_vendor ON purchase_orders (vendor_id)
WHERE
    deleted_at IS NULL;

CREATE INDEX idx_purchase_orders_status ON purchase_orders (status)
WHERE
    deleted_at IS NULL;

CREATE INDEX idx_purchase_orders_order_date ON purchase_orders (order_date DESC)
WHERE
    deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS
    purchase_order_lines (
        id UUID NOT NULL DEFAULT uuidv7 (),
        po_id UUID NOT NULL,
        item_id UUID NOT NULL,
        ordered_qty DECIMAL(15, 3) NOT NULL CHECK (ordered_qty > 0), -- theo purchase_uom
        purchase_uom VARCHAR(100) NOT NULL, -- SNAPSHOT: 'Phuy 250kg' | 'kg'
        conversion_factor DECIMAL(15, 6) NOT NULL DEFAULT 1, -- SNAPSHOT: 1 purchase_uom = factor base_uom
        ordered_qty_base DECIMAL(15, 6) GENERATED ALWAYS AS (ordered_qty * conversion_factor) STORED,
        unit_price DECIMAL(15, 4), -- giá theo purchase_uom
        vat_rate_pct DECIMAL(5, 2) NOT NULL DEFAULT 0, -- VAT %/dòng (0 | 5 | 8 | 10)
        line_amount DECIMAL(15, 2) GENERATED ALWAYS AS (ordered_qty * unit_price) STORED, -- thành tiền dòng (chưa VAT), theo currency PO
        -- Chuẩn hoá cho phân tích giá. Generated chỉ ref cột thường (PG không cho ref generated khác).
        unit_price_base DECIMAL(15, 6) GENERATED ALWAYS AS (unit_price / conversion_factor) STORED, -- giá / base_uom, theo currency
        line_vat_amount DECIMAL(15, 2) GENERATED ALWAYS AS (ordered_qty * unit_price * vat_rate_pct / 100) STORED, -- tiền VAT dòng, theo currency
        line_amount_with_vat DECIMAL(15, 2) GENERATED ALWAYS AS (
            ordered_qty * unit_price * (1 + vat_rate_pct / 100)
        ) STORED, -- thành tiền có VAT
        received_qty DECIMAL(15, 6) NOT NULL DEFAULT 0, -- theo base_uom, auto sync bởi trigger
        sequence_no INT,
        notes TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_purchase_order_lines PRIMARY KEY (id),
        CONSTRAINT chk_po_lines_received_qty CHECK (received_qty >= 0),
        CONSTRAINT chk_po_lines_conversion_factor CHECK (conversion_factor > 0),
        CONSTRAINT chk_po_lines_vat CHECK (
            vat_rate_pct >= 0
            AND vat_rate_pct <= 100
        )
    );

CREATE INDEX idx_po_lines_po ON purchase_order_lines (po_id);

CREATE INDEX idx_po_lines_item ON purchase_order_lines (item_id);

-- ==========================================================
-- LÔ HÀNG (LOTS)
-- ==========================================================
-- TRẠNG THÁI CHẤT LƯỢNG của vật tư — KHÁC với trạng thái chứng từ (goods_receipts.status).
-- Ghi sổ chứng từ và "hàng dùng được chưa" là hai việc độc lập: GR đã POSTED mà lô vẫn đang
-- chờ QC là trạng thái phổ biến nhất, gộp một cột sẽ không diễn tả được.
--   QUARANTINE = đang ở kho TẠM TRỮ, chờ IQC
--   RELEASED   = QC đạt, đã sang kho BẢO QUẢN -> sản xuất mới được lĩnh
--   REJECTED   = QC không đạt -> trả NCC / huỷ
CREATE TYPE lot_status AS ENUM('QUARANTINE', 'RELEASED', 'REJECTED');

CREATE TABLE
    lots (
        id UUID NOT NULL DEFAULT uuidv7 (),
        item_id UUID NOT NULL,
        lot_code VARCHAR(50) NOT NULL, -- mã lô nội bộ; trg tự sinh nếu bỏ trống
        vendor_lot_code VARCHAR(100), -- số lô in trên thùng của NCC
        status lot_status NOT NULL DEFAULT 'QUARANTINE',
        mfg_date DATE,
        expiry_date DATE, -- trg tự tính từ items.shelf_life_days nếu bỏ trống
        -- CỐ Ý KHÔNG có storage_bin_id: một lô nằm được ở NHIỀU bin cùng lúc (chuyển một phần,
        -- QC đạt 800/1000kg...) nên một cột sẽ nói dối. Hỏi "lô đang ở đâu" bằng
        -- v_inventory_on_hand — sổ kho là nguồn sự thật duy nhất về vị trí và số lượng.
        received_at TIMESTAMPTZ (3),
        released_at TIMESTAMPTZ (3),
        rejected_at TIMESTAMPTZ (3),
        notes TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_lots PRIMARY KEY (id),
        CONSTRAINT uq_lots_item_code UNIQUE (item_id, lot_code),
        CONSTRAINT chk_lots_expiry CHECK (
            expiry_date IS NULL
            OR mfg_date IS NULL
            OR expiry_date > mfg_date
        ),
        CONSTRAINT chk_lots_released CHECK (
            status <> 'RELEASED'
            OR released_at IS NOT NULL
        ),
        CONSTRAINT chk_lots_rejected CHECK (
            status <> 'REJECTED'
            OR rejected_at IS NOT NULL
        )
    );

CREATE INDEX idx_lots_item_status ON lots (item_id, status);

CREATE INDEX idx_lots_expiry ON lots (expiry_date)
WHERE
    status = 'RELEASED';

-- phục vụ FEFO
-- ==========================================================
-- NHẬN HÀNG (GOODS RECEIPTS)
-- ==========================================================
-- Phiếu nhận hàng là TRỤC VẬT LÝ: hàng đã về chưa, bao nhiêu, lô nào. Nó KHÔNG phụ thuộc hoá
-- đơn (xem vendor_invoices — trục tài chính). Hàng về trước hoá đơn cả tuần là chuyện thường,
-- và hàng xách tay thì không bao giờ có hoá đơn; buộc GR vào hoá đơn sẽ khiến hàng nằm ở kho
-- mà hệ thống không ghi nhận được.
CREATE TYPE gr_source_type AS ENUM('PURCHASE', 'HAND_CARRY', 'RETURN', 'ADJUSTMENT');

-- PURCHASE   = mua thường, có NCC trong danh mục (mặc định)
-- HAND_CARRY = xách tay: không PO, không hoá đơn, không NCC chính thức
-- RETURN     = trả về từ sản xuất
-- ADJUSTMENT = nhập điều chỉnh kiểm kê
CREATE TABLE IF NOT EXISTS
    goods_receipts (
        id UUID NOT NULL DEFAULT uuidv7 (),
        gr_number VARCHAR(50) NOT NULL,
        vendor_id UUID, -- 1 phiếu nhận = 1 NCC (link PO ở mức line, có thể nhiều PO cùng NCC);
        -- NULL khi không có NCC chính thức (hàng xách tay, trả về, điều chỉnh)
        source_type gr_source_type NOT NULL DEFAULT 'PURCHASE',
        source_note VARCHAR(255), -- nguồn tự do khi không có NCC: "mua tại ABC Store, HK"
        received_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        received_by UUID NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'DRAFT', -- DRAFT | POSTED | CANCELLED
        posted_at TIMESTAMPTZ (3),
        currency VARCHAR(3) NOT NULL DEFAULT 'VND', -- VND | USD (hàng xách tay từ nước ngoài có giá ngoại tệ)
        exchange_rate DECIMAL(15, 6) NOT NULL DEFAULT 1, -- 1 currency = exchange_rate VND
        notes TEXT,
        deleted_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_goods_receipts PRIMARY KEY (id),
        CONSTRAINT uq_goods_receipts_no UNIQUE (gr_number),
        CONSTRAINT chk_goods_receipts_status CHECK (status IN ('DRAFT', 'POSTED', 'CANCELLED')),
        CONSTRAINT chk_goods_receipts_posted CHECK (
            (status <> 'POSTED')
            OR posted_at IS NOT NULL
        ),
        -- Mua thường thì BẮT BUỘC có NCC; chỉ các nguồn còn lại mới được để trống.
        CONSTRAINT chk_gr_source_vendor CHECK (
            source_type <> 'PURCHASE'
            OR vendor_id IS NOT NULL
        ),
        CONSTRAINT chk_gr_currency CHECK (currency IN ('VND', 'USD')),
        CONSTRAINT chk_gr_exchange_rate CHECK (exchange_rate > 0),
        CONSTRAINT chk_gr_vnd_rate CHECK (
            currency <> 'VND'
            OR exchange_rate = 1
        )
    );

CREATE INDEX idx_goods_receipts_vendor ON goods_receipts (vendor_id)
WHERE
    deleted_at IS NULL;

CREATE INDEX idx_goods_receipts_received_at ON goods_receipts (received_at DESC)
WHERE
    deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS
    goods_receipt_lines (
        id UUID NOT NULL DEFAULT uuidv7 (),
        gr_id UUID NOT NULL,
        po_line_id UUID, -- nullable cho direct receipt
        item_id UUID NOT NULL,
        lot_id UUID, -- lô được tạo cho dòng nhập này; NULL khi item không quản lý lô
        -- (bắt buộc khi items.is_lot_managed — ép bằng trg_gr_lines_check_lot)
        storage_bin_id UUID NOT NULL, -- bin cụ thể trong zone
        received_qty DECIMAL(15, 3) NOT NULL CHECK (received_qty > 0), -- theo receipt_uom
        receipt_uom VARCHAR(100) NOT NULL, -- SNAPSHOT: 'Phuy 250kg' | 'kg'
        conversion_factor DECIMAL(15, 6) NOT NULL DEFAULT 1, -- SNAPSHOT: 1 receipt_uom = factor base_uom
        received_qty_base DECIMAL(15, 6) GENERATED ALWAYS AS (received_qty * conversion_factor) STORED,
        -- GIÁ VỐN NHẬP — nguồn sự thật cho giá tồn kho, áp dụng MỌI phiếu nhận:
        --   có PO  -> trg_gr_lines_fill_cost lấy từ PO line (giá thực nhận vẫn sửa đè được)
        --   không PO (hàng xách tay) -> app truyền tay; đây là chỗ DUY NHẤT giữ giá của nó
        unit_cost DECIMAL(15, 4), -- theo receipt_uom, theo currency của GR
        line_cost DECIMAL(15, 2) GENERATED ALWAYS AS (received_qty * unit_cost) STORED,
        unit_cost_base DECIMAL(15, 6) GENERATED ALWAYS AS (unit_cost / conversion_factor) STORED,
        package_count INT, -- số package được tạo (1+)
        notes TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_goods_receipt_lines PRIMARY KEY (id),
        CONSTRAINT chk_gr_lines_package_count CHECK (
            package_count IS NULL
            OR package_count > 0
        ),
        CONSTRAINT chk_gr_lines_conversion_factor CHECK (conversion_factor > 0),
        CONSTRAINT chk_gr_lines_unit_cost CHECK (
            unit_cost IS NULL
            OR unit_cost >= 0
        )
    );

CREATE INDEX idx_gr_lines_gr_item ON goods_receipt_lines (gr_id, item_id);

CREATE INDEX idx_gr_lines_po_line ON goods_receipt_lines (po_line_id)
WHERE
    po_line_id IS NOT NULL;

CREATE INDEX idx_gr_lines_lot ON goods_receipt_lines (lot_id);

-- ==========================================================
-- HOÁ ĐƠN NCC (VENDOR INVOICES)
-- ==========================================================
-- TRỤC TÀI CHÍNH, độc lập với trục vật lý (goods_receipts) và trục kho (lots.status):
-- nợ ai bao nhiêu, VAT có khấu trừ được không. Hàng xách tay không có dòng nào ở đây —
-- đó chính là ý nghĩa của việc tách bảng.
CREATE TABLE IF NOT EXISTS
    vendor_invoices (
        id UUID NOT NULL DEFAULT uuidv7 (),
        invoice_number VARCHAR(50) NOT NULL, -- SỐ CỦA NCC — KHÔNG dùng fn_next_doc_number
        invoice_series VARCHAR(20), -- ký hiệu hoá đơn VN, vd '1C25TAA'
        vendor_id UUID NOT NULL, -- hoá đơn luôn có người phát hành
        invoice_date DATE NOT NULL,
        received_date DATE, -- ngày mình nhận được hoá đơn
        due_date DATE, -- hạn thanh toán
        currency VARCHAR(3) NOT NULL DEFAULT 'VND',
        exchange_rate DECIMAL(15, 6) NOT NULL DEFAULT 1,
        subtotal DECIMAL(15, 2) NOT NULL DEFAULT 0, -- = SUM(line_amount), auto sync bởi trigger
        tax_amount DECIMAL(15, 2) NOT NULL DEFAULT 0, -- = SUM(line_vat_amount), auto sync bởi trigger
        shipping_fee DECIMAL(15, 2) NOT NULL DEFAULT 0,
        discount_amount DECIMAL(15, 2) NOT NULL DEFAULT 0,
        total_amount DECIMAL(15, 2) GENERATED ALWAYS AS (
            subtotal + shipping_fee + tax_amount - discount_amount
        ) STORED,
        total_amount_vnd DECIMAL(15, 2) GENERATED ALWAYS AS (
            (
                subtotal + shipping_fee + tax_amount - discount_amount
            ) * exchange_rate
        ) STORED,
        status VARCHAR(20) NOT NULL DEFAULT 'DRAFT', -- DRAFT | POSTED | CANCELLED
        posted_at TIMESTAMPTZ (3),
        notes TEXT,
        deleted_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_vendor_invoices PRIMARY KEY (id),
        -- Hai NCC khác nhau được phép trùng số hoá đơn -> khoá phải gồm vendor.
        -- NULLS NOT DISTINCT (PG15+): invoice_series bỏ trống vẫn không lách được trùng.
        CONSTRAINT uq_vendor_invoices_no UNIQUE NULLS NOT DISTINCT (vendor_id, invoice_series, invoice_number),
        CONSTRAINT chk_vendor_invoices_status CHECK (status IN ('DRAFT', 'POSTED', 'CANCELLED')),
        CONSTRAINT chk_vendor_invoices_posted CHECK (
            status <> 'POSTED'
            OR posted_at IS NOT NULL
        ),
        CONSTRAINT chk_vendor_invoices_currency CHECK (currency IN ('VND', 'USD')),
        CONSTRAINT chk_vendor_invoices_rate CHECK (exchange_rate > 0),
        CONSTRAINT chk_vendor_invoices_vnd_rate CHECK (
            currency <> 'VND'
            OR exchange_rate = 1
        ),
        CONSTRAINT chk_vendor_invoices_amounts CHECK (
            subtotal >= 0
            AND shipping_fee >= 0
            AND tax_amount >= 0
            AND discount_amount >= 0
        )
    );

CREATE INDEX idx_vendor_invoices_vendor ON vendor_invoices (vendor_id)
WHERE
    deleted_at IS NULL;

CREATE INDEX idx_vendor_invoices_date ON vendor_invoices (invoice_date DESC)
WHERE
    deleted_at IS NULL;

CREATE INDEX idx_vendor_invoices_status ON vendor_invoices (status)
WHERE
    deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS
    vendor_invoice_lines (
        id UUID NOT NULL DEFAULT uuidv7 (),
        invoice_id UUID NOT NULL,
        gr_line_id UUID, -- nối về dòng nhận (đối chiếu 3 chiều); NULL cho dòng dịch vụ/cước
        po_line_id UUID, -- đối chiếu trực tiếp với đơn đặt
        item_id UUID NOT NULL,
        qty DECIMAL(15, 3) NOT NULL CHECK (qty > 0), -- theo invoice_uom
        invoice_uom VARCHAR(100) NOT NULL, -- SNAPSHOT
        conversion_factor DECIMAL(15, 6) NOT NULL DEFAULT 1, -- SNAPSHOT: 1 invoice_uom = factor base_uom
        qty_base DECIMAL(15, 6) GENERATED ALWAYS AS (qty * conversion_factor) STORED,
        unit_price DECIMAL(15, 4), -- theo invoice_uom
        vat_rate_pct DECIMAL(5, 2) NOT NULL DEFAULT 0,
        line_amount DECIMAL(15, 2) GENERATED ALWAYS AS (qty * unit_price) STORED,
        unit_price_base DECIMAL(15, 6) GENERATED ALWAYS AS (unit_price / conversion_factor) STORED,
        line_vat_amount DECIMAL(15, 2) GENERATED ALWAYS AS (qty * unit_price * vat_rate_pct / 100) STORED,
        line_amount_with_vat DECIMAL(15, 2) GENERATED ALWAYS AS (qty * unit_price * (1 + vat_rate_pct / 100)) STORED,
        sequence_no INT,
        notes TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_vendor_invoice_lines PRIMARY KEY (id),
        CONSTRAINT chk_vi_lines_conversion_factor CHECK (conversion_factor > 0),
        CONSTRAINT chk_vi_lines_vat CHECK (
            vat_rate_pct >= 0
            AND vat_rate_pct <= 100
        )
    );

CREATE INDEX idx_vi_lines_invoice ON vendor_invoice_lines (invoice_id);

CREATE INDEX idx_vi_lines_item ON vendor_invoice_lines (item_id);

CREATE INDEX idx_vi_lines_gr_line ON vendor_invoice_lines (gr_line_id)
WHERE
    gr_line_id IS NOT NULL;

CREATE INDEX idx_vi_lines_po_line ON vendor_invoice_lines (po_line_id)
WHERE
    po_line_id IS NOT NULL;

-- ==========================================================
-- SỔ KHO (INVENTORY MOVEMENTS)
-- ==========================================================
-- NGUỒN SỰ THẬT DUY NHẤT cho tồn kho. Mọi chứng từ (nhận hàng, chuyển kho, xuất sản xuất...)
-- đều đẻ dòng vào đây; tồn kho = SUM(qty_base).
--
-- APPEND-ONLY: không sửa, không xoá. Sai thì ghi BÚT TOÁN ĐẢO (dòng âm).
-- Đây là điểm khác BẢN CHẤT với fn_po_sync_totals / fn_recalc_po_line_received: hai hàm đó
-- recalc-from-scratch được vì chúng tính GIÁ TRỊ DẪN XUẤT. Sổ kế toán thì phải giữ lịch sử —
-- tính lại là mất dấu vết, và không đối chiếu được với kỳ đã khoá sổ.
CREATE TYPE movement_type AS ENUM(
    'RECEIPT', -- nhập từ phiếu nhận hàng
    'TRANSFER_OUT',
    'TRANSFER_IN', -- chuyển kho/bin (tạm trữ -> bảo quản)
    'ISSUE',
    'PRODUCTION_IN', -- xuất sản xuất / nhập thành phẩm
    'ADJUSTMENT',
    'RETURN_OUT',
    'SCRAP' -- kiểm kê / trả NCC / huỷ
);

-- Khai đủ giá trị ngay từ đầu: ALTER TYPE ADD VALUE sau này không dùng được giá trị mới
-- trong cùng transaction vừa thêm nó.
CREATE TABLE
    inventory_movements (
        id UUID NOT NULL DEFAULT uuidv7 (),
        movement_type movement_type NOT NULL,
        movement_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        item_id UUID NOT NULL,
        lot_id UUID, -- NULL khi item không quản lý lô
        storage_bin_id UUID NOT NULL,
        qty_base NUMERIC(18, 6) NOT NULL, -- DƯƠNG = nhập, ÂM = xuất
        unit_cost_vnd NUMERIC(18, 6), -- giá vốn / base_uom, ĐÃ quy về VND
        -- Chứng từ gốc: FK nullable + CHECK ép đúng MỘT nguồn (giữ được toàn vẹn tham chiếu,
        -- khác với polymorphic source_doc_type/id vốn không FK được). Thêm loại chứng từ mới thì
        -- thêm cột ở đây VÀ thêm vào num_nonnulls bên dưới.
        gr_line_id UUID,
        transfer_line_id UUID,
        issue_line_id UUID,
        adjustment_line_id UUID,
        production_receipt_id UUID,
        reverses_movement_id UUID, -- dòng này đảo dòng nào (khi huỷ chứng từ)
        created_by UUID,
        notes TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        -- CỐ Ý KHÔNG CÓ updated_at: bảng bất biến. Khối DO cuối file lọc theo cột này nên tự bỏ qua.
        CONSTRAINT pk_inventory_movements PRIMARY KEY (id),
        CONSTRAINT chk_im_qty_nonzero CHECK (qty_base <> 0),
        CONSTRAINT chk_im_source CHECK (
            num_nonnulls (
                gr_line_id,
                transfer_line_id,
                issue_line_id,
                adjustment_line_id,
                production_receipt_id
            ) = 1
        )
    );

CREATE INDEX idx_im_stock ON inventory_movements (item_id, lot_id, storage_bin_id);

-- SUM tồn kho
CREATE INDEX idx_im_gr_line ON inventory_movements (gr_line_id)
WHERE
    gr_line_id IS NOT NULL;

CREATE INDEX idx_im_transfer_line ON inventory_movements (transfer_line_id)
WHERE
    transfer_line_id IS NOT NULL;

CREATE INDEX idx_im_issue_line ON inventory_movements (issue_line_id)
WHERE
    issue_line_id IS NOT NULL;

CREATE INDEX idx_im_adjustment_line ON inventory_movements (adjustment_line_id)
WHERE
    adjustment_line_id IS NOT NULL;

CREATE INDEX idx_im_production_receipt ON inventory_movements (production_receipt_id)
WHERE
    production_receipt_id IS NOT NULL;

CREATE INDEX idx_im_lot ON inventory_movements (lot_id);

-- truy vết lô
CREATE INDEX idx_im_at ON inventory_movements (movement_at DESC);

-- ==========================================================
-- CHUYỂN KHO (STOCK TRANSFERS)
-- ==========================================================
-- Đổi vị trí, KHÔNG đổi lượng và KHÔNG đổi giá vốn. Mỗi dòng đẻ HAI bút toán:
-- TRANSFER_OUT (âm, bin đi) + TRANSFER_IN (dương, bin đến).
-- Đây là chứng từ đóng luồng QC: tạm trữ -> (QC đạt) -> bảo quản.
CREATE TABLE IF NOT EXISTS
    stock_transfers (
        id UUID NOT NULL DEFAULT uuidv7 (),
        transfer_number VARCHAR(50) NOT NULL,
        transferred_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        transferred_by UUID NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
        posted_at TIMESTAMPTZ (3),
        reason VARCHAR(255),
        notes TEXT,
        deleted_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_stock_transfers PRIMARY KEY (id),
        CONSTRAINT uq_stock_transfers_no UNIQUE (transfer_number),
        CONSTRAINT chk_stock_transfers_status CHECK (status IN ('DRAFT', 'POSTED', 'CANCELLED')),
        CONSTRAINT chk_stock_transfers_posted CHECK (
            status <> 'POSTED'
            OR posted_at IS NOT NULL
        )
    );

CREATE INDEX idx_st_at ON stock_transfers (transferred_at DESC)
WHERE
    deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS
    stock_transfer_lines (
        id UUID NOT NULL DEFAULT uuidv7 (),
        transfer_id UUID NOT NULL,
        item_id UUID NOT NULL,
        lot_id UUID,
        from_bin_id UUID NOT NULL,
        to_bin_id UUID NOT NULL,
        qty_base NUMERIC(18, 6) NOT NULL CHECK (qty_base > 0),
        notes TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_stock_transfer_lines PRIMARY KEY (id),
        CONSTRAINT chk_stl_bins_differ CHECK (from_bin_id <> to_bin_id)
    );

CREATE INDEX idx_stl_transfer ON stock_transfer_lines (transfer_id);

CREATE INDEX idx_stl_item_lot ON stock_transfer_lines (item_id, lot_id);

-- ==========================================================
-- XUẤT KHO (STOCK ISSUES)
-- ==========================================================
-- Một chứng từ cho mọi kiểu xuất; issue_type quyết định movement_type ghi vào sổ.
CREATE TYPE issue_type AS ENUM(
    'PRODUCTION',
    'QC_SAMPLE',
    'RETURN_VENDOR',
    'SCRAP',
    'SALE'
);

CREATE TABLE IF NOT EXISTS
    stock_issues (
        id UUID NOT NULL DEFAULT uuidv7 (),
        issue_number VARCHAR(50) NOT NULL,
        issue_type issue_type NOT NULL,
        mo_id UUID, -- bắt buộc khi xuất cho sản xuất
        vendor_id UUID, -- khi trả hàng NCC
        issued_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        issued_by UUID NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
        posted_at TIMESTAMPTZ (3),
        reason VARCHAR(255),
        notes TEXT,
        deleted_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_stock_issues PRIMARY KEY (id),
        CONSTRAINT uq_stock_issues_no UNIQUE (issue_number),
        CONSTRAINT chk_stock_issues_status CHECK (status IN ('DRAFT', 'POSTED', 'CANCELLED')),
        CONSTRAINT chk_stock_issues_posted CHECK (
            status <> 'POSTED'
            OR posted_at IS NOT NULL
        ),
        -- Xuất sản xuất mà không gắn lệnh SX thì không truy vết được lô -> cấm.
        CONSTRAINT chk_stock_issues_mo CHECK (
            issue_type <> 'PRODUCTION'
            OR mo_id IS NOT NULL
        )
    );

CREATE INDEX idx_si_type ON stock_issues (issue_type)
WHERE
    deleted_at IS NULL;

CREATE INDEX idx_si_mo ON stock_issues (mo_id)
WHERE
    mo_id IS NOT NULL;

CREATE INDEX idx_si_at ON stock_issues (issued_at DESC)
WHERE
    deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS
    stock_issue_lines (
        id UUID NOT NULL DEFAULT uuidv7 (),
        issue_id UUID NOT NULL,
        item_id UUID NOT NULL,
        lot_id UUID,
        storage_bin_id UUID NOT NULL,
        qty_base NUMERIC(18, 6) NOT NULL CHECK (qty_base > 0), -- lượng XUẤT, luôn dương ở chứng từ
        notes TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_stock_issue_lines PRIMARY KEY (id)
    );

CREATE INDEX idx_sil_issue ON stock_issue_lines (issue_id);

CREATE INDEX idx_sil_item_lot ON stock_issue_lines (item_id, lot_id);

-- ==========================================================
-- ĐIỀU CHỈNH KIỂM KÊ (STOCK ADJUSTMENTS)
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    stock_adjustments (
        id UUID NOT NULL DEFAULT uuidv7 (),
        adjustment_number VARCHAR(50) NOT NULL,
        counted_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        counted_by UUID NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
        posted_at TIMESTAMPTZ (3),
        reason VARCHAR(255),
        notes TEXT,
        deleted_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_stock_adjustments PRIMARY KEY (id),
        CONSTRAINT uq_stock_adjustments_no UNIQUE (adjustment_number),
        CONSTRAINT chk_stock_adjustments_status CHECK (status IN ('DRAFT', 'POSTED', 'CANCELLED')),
        CONSTRAINT chk_stock_adjustments_posted CHECK (
            status <> 'POSTED'
            OR posted_at IS NOT NULL
        )
    );

CREATE INDEX idx_sa_at ON stock_adjustments (counted_at DESC)
WHERE
    deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS
    stock_adjustment_lines (
        id UUID NOT NULL DEFAULT uuidv7 (),
        adjustment_id UUID NOT NULL,
        item_id UUID NOT NULL,
        lot_id UUID,
        storage_bin_id UUID NOT NULL,
        system_qty_base NUMERIC(18, 6) NOT NULL, -- tồn theo sổ, CHỤP lúc lập phiếu
        counted_qty_base NUMERIC(18, 6) NOT NULL CHECK (counted_qty_base >= 0), -- đếm thực tế
        -- Chênh lệch chính là bút toán ADJUSTMENT: dương = thừa, âm = thiếu.
        diff_qty_base NUMERIC(18, 6) GENERATED ALWAYS AS (counted_qty_base - system_qty_base) STORED,
        notes TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_stock_adjustment_lines PRIMARY KEY (id)
    );

CREATE INDEX idx_sal_adjustment ON stock_adjustment_lines (adjustment_id);

CREATE INDEX idx_sal_item_lot ON stock_adjustment_lines (item_id, lot_id);

-- ==========================================================
-- LỆNH SẢN XUẤT (MANUFACTURING ORDERS)
-- ==========================================================
CREATE TYPE mo_status AS ENUM(
    'DRAFT',
    'RELEASED',
    'IN_PROGRESS',
    'COMPLETED',
    'CANCELLED'
);

CREATE TABLE IF NOT EXISTS
    manufacturing_orders (
        id UUID NOT NULL DEFAULT uuidv7 (),
        mo_number VARCHAR(50) NOT NULL,
        item_id UUID NOT NULL, -- thành phẩm / bán thành phẩm
        bom_id UUID NOT NULL, -- SNAPSHOT công thức đã dùng
        planned_qty_base NUMERIC(18, 6) NOT NULL CHECK (planned_qty_base > 0),
        produced_qty_base NUMERIC(18, 6) NOT NULL DEFAULT 0, -- auto sync từ production_receipts
        output_lot_id UUID, -- lô thành phẩm tạo ra
        status mo_status NOT NULL DEFAULT 'DRAFT',
        planned_start DATE,
        planned_end DATE,
        actual_start TIMESTAMPTZ (3),
        actual_end TIMESTAMPTZ (3),
        created_by UUID,
        notes TEXT,
        deleted_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_manufacturing_orders PRIMARY KEY (id),
        CONSTRAINT uq_manufacturing_orders_no UNIQUE (mo_number),
        CONSTRAINT chk_mo_produced CHECK (produced_qty_base >= 0)
    );

CREATE INDEX idx_mo_item ON manufacturing_orders (item_id)
WHERE
    deleted_at IS NULL;

CREATE INDEX idx_mo_status ON manufacturing_orders (status)
WHERE
    deleted_at IS NULL;

-- ĐỊNH MỨC ĐÃ CHỐT tại thời điểm lập MO — KHÔNG đọc lại BOM về sau. Công thức đổi thì lệnh
-- cũ phải giữ nguyên số đã tính, đúng tinh thần snapshot purchase_uom/conversion_factor.
CREATE TABLE IF NOT EXISTS
    mo_material_lines (
        id UUID NOT NULL DEFAULT uuidv7 (),
        mo_id UUID NOT NULL,
        component_item_id UUID NOT NULL,
        required_qty_base NUMERIC(18, 6) NOT NULL CHECK (required_qty_base > 0),
        issued_qty_base NUMERIC(18, 6) NOT NULL DEFAULT 0, -- auto sync từ stock_issues POSTED
        line_no SMALLINT,
        notes TEXT,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_mo_material_lines PRIMARY KEY (id),
        CONSTRAINT uq_mo_material_lines UNIQUE (mo_id, component_item_id, line_no),
        CONSTRAINT chk_mml_issued CHECK (issued_qty_base >= 0)
    );

CREATE INDEX idx_mml_mo ON mo_material_lines (mo_id);

CREATE INDEX idx_mml_component ON mo_material_lines (component_item_id);

-- NHẬP THÀNH PHẨM. Bảng PHẲNG (không có lines): một MO cho ra một item vào một lô,
-- mỗi lần nhập là một dòng — cho phép nhập nhiều đợt trong cùng lệnh.
CREATE TABLE IF NOT EXISTS
    production_receipts (
        id UUID NOT NULL DEFAULT uuidv7 (),
        pr_number VARCHAR(50) NOT NULL,
        mo_id UUID NOT NULL,
        item_id UUID NOT NULL,
        lot_id UUID,
        storage_bin_id UUID NOT NULL,
        qty_base NUMERIC(18, 6) NOT NULL CHECK (qty_base > 0),
        unit_cost_vnd NUMERIC(18, 6), -- giá thành ước tính / base_uom
        received_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        received_by UUID NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
        posted_at TIMESTAMPTZ (3),
        notes TEXT,
        deleted_at TIMESTAMPTZ (3),
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_production_receipts PRIMARY KEY (id),
        CONSTRAINT uq_production_receipts_no UNIQUE (pr_number),
        CONSTRAINT chk_pr_status CHECK (status IN ('DRAFT', 'POSTED', 'CANCELLED')),
        CONSTRAINT chk_pr_posted CHECK (
            status <> 'POSTED'
            OR posted_at IS NOT NULL
        )
    );

CREATE INDEX idx_pr_mo ON production_receipts (mo_id);

CREATE INDEX idx_pr_at ON production_receipts (received_at DESC)
WHERE
    deleted_at IS NULL;

-- -----------------------------------------------------------------------------
-- SINH SỐ CHỨNG TỪ (po_number/gr_number) — đếm theo (doc_type, tháng), reset mỗi tháng.
-- Nguyên tử: INSERT ... ON CONFLICT DO UPDATE khoá đúng MỘT dòng (doc_type, period) nên
-- hai caller song song nối đuôi nhau, mỗi bên nhận last_seq khác nhau. Rollback để lại lỗ
-- số (chấp nhận được cho số chứng từ; gapless thật sự cần serialize toàn cục, không đáng).
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_next_doc_number (p_doc_type TEXT) RETURNS TEXT LANGUAGE plpgsql AS $$
DECLARE
    v_period TEXT := to_char(NOW(), 'YYMM'); -- NOW() theo timezone DB (Asia/Ho_Chi_Minh)
    v_seq    INT;
BEGIN
    INSERT INTO document_number_counters (doc_type, period, last_seq)
    VALUES (p_doc_type, v_period, 1)
    ON CONFLICT (doc_type, period)
        DO UPDATE SET last_seq = document_number_counters.last_seq + 1
    RETURNING last_seq INTO v_seq;

    RETURN format('%s%s-%s', p_doc_type, v_period, lpad(v_seq::text, 4, '0'));
END
$$;

-- Tự gán po_number khi app bỏ trống. BEFORE INSERT chạy TRƯỚC khi kiểm NOT NULL nên điền
-- được cột NOT NULL để trống. Tính duy nhất vẫn có uq_purchase_orders_no bảo chứng.
CREATE
OR REPLACE FUNCTION fn_po_fill_number () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.po_number IS NULL THEN
        NEW.po_number := fn_next_doc_number('PO');
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_po_fill_number BEFORE INSERT ON purchase_orders FOR EACH ROW
EXECUTE FUNCTION fn_po_fill_number ();

-- -----------------------------------------------------------------------------
-- ĐỒNG BỘ TỔNG TIỀN PO: subtotal = SUM(line_amount), tax_amount = SUM(line_vat_amount).
-- Hai cột GENERATED total_amount(_vnd) tự cập nhật theo.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_po_sync_totals () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    v_po_id UUID := COALESCE(NEW.po_id, OLD.po_id);
BEGIN
    -- Khoá dòng PO TRƯỚC khi tính tổng: ở READ COMMITTED hai session cùng chèn dòng vào một
    -- PO, nếu không khoá thì mỗi bên SUM ra tổng thiếu dòng của bên kia -> lost update.
    -- FOR UPDATE nối đuôi, statement SUM sau đó lấy snapshot mới đã gồm dòng vừa commit.
    PERFORM 1 FROM purchase_orders WHERE id = v_po_id FOR UPDATE;

    UPDATE purchase_orders p
    SET subtotal   = COALESCE(s.subtotal, 0),
        tax_amount = COALESCE(s.vat, 0)
    FROM (SELECT SUM(line_amount)     AS subtotal,
                 SUM(line_vat_amount) AS vat
          FROM purchase_order_lines
          WHERE po_id = v_po_id) s
    WHERE p.id = v_po_id; -- PO bị xoá (CASCADE) -> 0 dòng, no-op, không lỗi

    -- Dòng bị chuyển sang PO khác: đồng bộ lại cả PO cũ.
    IF TG_OP = 'UPDATE' AND NEW.po_id <> OLD.po_id THEN
        PERFORM 1 FROM purchase_orders WHERE id = OLD.po_id FOR UPDATE;
        UPDATE purchase_orders p
        SET subtotal   = COALESCE(s.subtotal, 0),
            tax_amount = COALESCE(s.vat, 0)
        FROM (SELECT SUM(line_amount)     AS subtotal,
                     SUM(line_vat_amount) AS vat
              FROM purchase_order_lines
              WHERE po_id = OLD.po_id) s
        WHERE p.id = OLD.po_id;
    END IF;

    RETURN NULL;
END
$$;

-- UPDATE OF chỉ liệt kê cột đầu vào của line_amount/line_vat_amount + po_id (ca chuyển PO);
-- sửa notes/received_qty... không kích hoạt tính lại thừa.
CREATE TRIGGER trg_po_lines_sync_totals
AFTER INSERT
OR DELETE
OR
UPDATE OF po_id,
ordered_qty,
unit_price,
vat_rate_pct ON purchase_order_lines FOR EACH ROW
EXECUTE FUNCTION fn_po_sync_totals ();

-- -----------------------------------------------------------------------------
-- MẶC ĐỊNH CHO LÔ: mã lô, hạn dùng, trạng thái theo requires_qc.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_lots_fill_defaults () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    v_shelf_life INTEGER;
    v_requires_qc BOOLEAN;
BEGIN
    IF NEW.lot_code IS NULL THEN
        NEW.lot_code := fn_next_doc_number('LOT');
    END IF;

    SELECT shelf_life_days, requires_qc INTO v_shelf_life, v_requires_qc
    FROM items WHERE id = NEW.item_id;

    -- Đây là chỗ DUY NHẤT khiến items.shelf_life_days có tác dụng thật.
    IF NEW.expiry_date IS NULL AND NEW.mfg_date IS NOT NULL AND v_shelf_life IS NOT NULL THEN
        NEW.expiry_date := NEW.mfg_date + v_shelf_life;
    END IF;

    -- Item không phải kiểm nhập thì không có gì để chờ -> dùng được ngay.
    IF v_requires_qc IS FALSE AND NEW.status = 'QUARANTINE' THEN
        NEW.status := 'RELEASED';
        NEW.released_at := COALESCE(NEW.released_at, NOW());
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER trg_lots_fill_defaults BEFORE INSERT ON lots FOR EACH ROW
EXECUTE FUNCTION fn_lots_fill_defaults ();

-- Bản đối xứng của fn_po_fill_number cho phiếu nhận hàng.
CREATE
OR REPLACE FUNCTION fn_gr_fill_number () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.gr_number IS NULL THEN
        NEW.gr_number := fn_next_doc_number('GR');
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_gr_fill_number BEFORE INSERT ON goods_receipts FOR EACH ROW
EXECUTE FUNCTION fn_gr_fill_number ();

-- Item quản lý theo lô thì dòng nhập BẮT BUỘC có lô. Quy tắc đọc sang bảng items nên
-- CHECK không làm được — cùng nhóm ràng buộc liên bảng với fn_uom_factor_to_base.
CREATE
OR REPLACE FUNCTION fn_gr_lines_check_lot () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.lot_id IS NULL
        AND (SELECT is_lot_managed FROM items WHERE id = NEW.item_id) THEN
        RAISE EXCEPTION 'Item % quản lý theo lô, dòng nhập phải có lot_id',
            COALESCE((SELECT code FROM items WHERE id = NEW.item_id), NEW.item_id::text)
            USING ERRCODE = 'LOT01',
                HINT = 'Tạo lô trong bảng lots rồi gán lot_id, hoặc tắt items.is_lot_managed.';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_gr_lines_check_lot BEFORE INSERT
OR
UPDATE OF item_id,
lot_id ON goods_receipt_lines FOR EACH ROW
EXECUTE FUNCTION fn_gr_lines_check_lot ();

-- Giá vốn nhập bỏ trống mà dòng có gắn PO -> lấy từ đơn đặt.
-- PHẢI quy đổi QUA BASE, không copy thẳng unit_price: receipt_uom có thể khác purchase_uom
-- (đặt theo 'Phuy 250kg', nhận theo 'kg') -> copy thẳng sẽ sai gấp 250 lần.
-- Tái dùng cột GENERATED purchase_order_lines.unit_price_base đã có sẵn.
CREATE
OR REPLACE FUNCTION fn_gr_lines_fill_cost () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.unit_cost IS NULL AND NEW.po_line_id IS NOT NULL THEN
        SELECT unit_price_base * NEW.conversion_factor
        INTO NEW.unit_cost
        FROM purchase_order_lines
        WHERE id = NEW.po_line_id;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_gr_lines_fill_cost BEFORE INSERT
OR
UPDATE OF po_line_id,
conversion_factor,
unit_cost ON goods_receipt_lines FOR EACH ROW
EXECUTE FUNCTION fn_gr_lines_fill_cost ();

-- -----------------------------------------------------------------------------
-- ĐỒNG BỘ TỔNG TIỀN HOÁ ĐƠN NCC — cùng khuôn với fn_po_sync_totals, kể cả việc khoá
-- dòng cha FOR UPDATE trước khi SUM (lost update ở READ COMMITTED).
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_vendor_invoice_sync_totals () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    v_invoice_id UUID := COALESCE(NEW.invoice_id, OLD.invoice_id);
BEGIN
    PERFORM 1 FROM vendor_invoices WHERE id = v_invoice_id FOR UPDATE;

    UPDATE vendor_invoices i
    SET subtotal   = COALESCE(s.subtotal, 0),
        tax_amount = COALESCE(s.vat, 0)
    FROM (SELECT SUM(line_amount)     AS subtotal,
                 SUM(line_vat_amount) AS vat
          FROM vendor_invoice_lines
          WHERE invoice_id = v_invoice_id) s
    WHERE i.id = v_invoice_id;

    -- Dòng bị chuyển sang hoá đơn khác: đồng bộ lại cả bên cũ.
    IF TG_OP = 'UPDATE' AND NEW.invoice_id <> OLD.invoice_id THEN
        PERFORM 1 FROM vendor_invoices WHERE id = OLD.invoice_id FOR UPDATE;
        UPDATE vendor_invoices i
        SET subtotal   = COALESCE(s.subtotal, 0),
            tax_amount = COALESCE(s.vat, 0)
        FROM (SELECT SUM(line_amount)     AS subtotal,
                     SUM(line_vat_amount) AS vat
              FROM vendor_invoice_lines
              WHERE invoice_id = OLD.invoice_id) s
        WHERE i.id = OLD.invoice_id;
    END IF;

    RETURN NULL;
END
$$;

CREATE TRIGGER trg_vendor_invoice_lines_sync_totals
AFTER INSERT
OR DELETE
OR
UPDATE OF invoice_id,
qty,
unit_price,
vat_rate_pct ON vendor_invoice_lines FOR EACH ROW
EXECUTE FUNCTION fn_vendor_invoice_sync_totals ();

-- -----------------------------------------------------------------------------
-- SỔ KHO BẤT BIẾN. Không sửa, không xoá — sai thì ghi bút toán đảo.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_im_append_only () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Sổ kho là bất biến: không được % dòng đã ghi', lower(TG_OP)
        USING ERRCODE = 'INV01',
            HINT = 'Ghi một dòng bút toán đảo (qty_base âm, reverses_movement_id) thay vì sửa/xoá.';
END
$$;

CREATE TRIGGER trg_im_append_only BEFORE
UPDATE
OR DELETE ON inventory_movements FOR EACH ROW
EXECUTE FUNCTION fn_im_append_only ();

-- -----------------------------------------------------------------------------
-- QUY TẮC CHỨNG TỪ DÙNG CHUNG cho MỌI loại phiếu (nhận hàng, hoá đơn, chuyển kho, xuất kho,
-- kiểm kê, nhập thành phẩm). Viết một lần, gắn nhiều bảng — sáu bản sao sẽ trôi lệch nhau.
-- Tham số hoá bằng TG_ARGV + dynamic SQL, cùng kỹ thuật hai khối DO cuối file.
-- -----------------------------------------------------------------------------
-- KHOÁ DÒNG CỦA CHỨNG TỪ ĐÃ GHI SỔ. Sổ kho không tính lại được, nên dòng đã sinh ra bút toán
-- PHẢI đứng yên. TG_ARGV[0] = bảng cha, TG_ARGV[1] = cột FK trỏ cha.
CREATE
OR REPLACE FUNCTION fn_doc_lines_frozen () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    v_row    JSONB;
    v_status TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := to_jsonb(OLD);
    ELSE
        v_row := to_jsonb(NEW);
    END IF;

    EXECUTE format('SELECT status::text FROM %I WHERE id = $1', TG_ARGV[0])
        INTO v_status USING (v_row ->> TG_ARGV[1])::UUID;

    -- Chứng từ cha đã bị xoá (cascade) -> không cản trở việc dọn dòng con.
    IF v_status IS NULL OR v_status = 'DRAFT' THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;

    RAISE EXCEPTION 'Chứng từ % đang ở trạng thái % — không sửa được dòng', TG_ARGV[0], v_status
        USING ERRCODE = 'DOC01',
            HINT = 'Huỷ chứng từ rồi lập cái mới; chứng từ đã ghi sổ không được sửa.';
END
$$;

-- Chặn CANCELLED -> POSTED: chứng từ đã huỷ mà sống lại sẽ đẻ bút toán lần hai.
CREATE
OR REPLACE FUNCTION fn_doc_status_flow () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    IF NOT ((OLD.status = 'DRAFT' AND NEW.status IN ('POSTED', 'CANCELLED'))
        OR (OLD.status = 'POSTED' AND NEW.status = 'CANCELLED')) THEN
        RAISE EXCEPTION 'Chuyển trạng thái % không hợp lệ: % -> %', TG_TABLE_NAME, OLD.status, NEW.status
            USING ERRCODE = 'DOC02',
                HINT = 'Chỉ cho DRAFT->POSTED, DRAFT->CANCELLED, POSTED->CANCELLED.';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER trg_gr_lines_frozen BEFORE INSERT
OR
UPDATE
OR DELETE ON goods_receipt_lines FOR EACH ROW
EXECUTE FUNCTION fn_doc_lines_frozen ('goods_receipts', 'gr_id');

CREATE TRIGGER trg_gr_status_flow BEFORE
UPDATE OF status ON goods_receipts FOR EACH ROW
EXECUTE FUNCTION fn_doc_status_flow ();

CREATE TRIGGER trg_vi_lines_frozen BEFORE INSERT
OR
UPDATE
OR DELETE ON vendor_invoice_lines FOR EACH ROW
EXECUTE FUNCTION fn_doc_lines_frozen ('vendor_invoices', 'invoice_id');

CREATE TRIGGER trg_vi_status_flow BEFORE
UPDATE OF status ON vendor_invoices FOR EACH ROW
EXECUTE FUNCTION fn_doc_status_flow ();

-- -----------------------------------------------------------------------------
-- KIỂM TỒN ĐỦ TRƯỚC MỌI BÚT TOÁN ÂM — nơi tập trung toàn bộ rủi ro tồn âm.
-- Khoá theo (item, lot, bin) RỒI MỚI SUM: ở READ COMMITTED hai người cùng xuất một lô đều
-- đọc thấy đủ tồn rồi cùng ghi -> âm. Lock xong, statement SUM sau lấy snapshot mới.
-- Đường NHẬP không cần gọi (chỉ làm tăng tồn), nhưng BÚT TOÁN ĐẢO thì cần.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_assert_stock_available (
    p_item_id UUID,
    p_lot_id UUID,
    p_bin_id UUID,
    p_qty_needed NUMERIC
) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    v_available NUMERIC;
BEGIN
    PERFORM pg_advisory_xact_lock(
            hashtext(p_item_id::text || '|' || COALESCE(p_lot_id::text, '') || '|' || p_bin_id::text));

    SELECT COALESCE(SUM(qty_base), 0)
    INTO v_available
    FROM inventory_movements
    WHERE item_id = p_item_id
      AND lot_id IS NOT DISTINCT FROM p_lot_id
      AND storage_bin_id = p_bin_id;

    IF v_available < p_qty_needed THEN
        RAISE EXCEPTION 'Không đủ tồn: cần %, còn % (item %, lô %, bin %)',
            p_qty_needed, v_available,
            COALESCE((SELECT code FROM items WHERE id = p_item_id), p_item_id::text),
            COALESCE((SELECT lot_code FROM lots WHERE id = p_lot_id), '—'),
            COALESCE((SELECT code FROM storage_bins WHERE id = p_bin_id), p_bin_id::text)
            USING ERRCODE = 'INV02';
    END IF;
END
$$;

-- -----------------------------------------------------------------------------
-- GHI SỔ TỪ PHIẾU NHẬN.
--   -> POSTED    : mỗi dòng hàng đẻ một bút toán RECEIPT (qty dương)
--   -> CANCELLED : đẻ BÚT TOÁN ĐẢO (qty âm), KHÔNG đụng dòng cũ
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_gr_post_to_ledger () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'POSTED' THEN
        INSERT INTO inventory_movements (movement_type, movement_at, item_id, lot_id,
                                         storage_bin_id, qty_base, unit_cost_vnd,
                                         gr_line_id, created_by)
        SELECT 'RECEIPT',
               NEW.posted_at,
               grl.item_id,
               grl.lot_id,
               grl.storage_bin_id,
               grl.received_qty_base, -- theo BASE, không phải received_qty
               -- unit_cost_base (không phải unit_cost: sổ ghi theo base) rồi quy về VND,
               -- vì tồn kho là tài sản hạch toán bằng VND còn phiếu có thể là USD.
               grl.unit_cost_base * NEW.exchange_rate,
               grl.id,
               NEW.received_by
        FROM goods_receipt_lines grl
        WHERE grl.gr_id = NEW.id;

    ELSIF NEW.status = 'CANCELLED' AND OLD.status = 'POSTED' THEN
        -- Bút toán đảo là bút toán ÂM: huỷ một phiếu mà hàng đã xuất đi rồi sẽ kéo tồn xuống
        -- âm. Chặn ở đây là ĐÚNG nghiệp vụ — không huỷ được phiếu đã tiêu thụ.
        PERFORM fn_assert_stock_available(im.item_id, im.lot_id, im.storage_bin_id, im.qty_base)
        FROM inventory_movements im
                 JOIN goods_receipt_lines grl ON grl.id = im.gr_line_id
        WHERE grl.gr_id = NEW.id
          AND im.reverses_movement_id IS NULL
          AND NOT EXISTS (SELECT 1 FROM inventory_movements r WHERE r.reverses_movement_id = im.id);

        INSERT INTO inventory_movements (movement_type, movement_at, item_id, lot_id,
                                         storage_bin_id, qty_base, unit_cost_vnd,
                                         gr_line_id, reverses_movement_id, created_by)
        SELECT im.movement_type,
               NOW(),
               im.item_id,
               im.lot_id,
               im.storage_bin_id,
               -im.qty_base, -- đảo dấu
               im.unit_cost_vnd,
               im.gr_line_id,
               im.id,
               NEW.received_by
        FROM inventory_movements im
                 JOIN goods_receipt_lines grl ON grl.id = im.gr_line_id
        WHERE grl.gr_id = NEW.id
          AND im.reverses_movement_id IS NULL -- chỉ đảo bút toán gốc
          AND NOT EXISTS (SELECT 1
                          FROM inventory_movements r
                          WHERE r.reverses_movement_id = im.id); -- đã đảo rồi thì thôi
    END IF;

    RETURN NULL;
END
$$;

-- WHEN (...IS DISTINCT FROM...): UPDATE ghi lại đúng giá trị cũ không được sinh bút toán trùng.
CREATE TRIGGER trg_gr_post_to_ledger
AFTER
UPDATE OF status ON goods_receipts FOR EACH ROW WHEN (
    OLD.status IS DISTINCT
    FROM
        NEW.status
)
EXECUTE FUNCTION fn_gr_post_to_ledger ();

-- -----------------------------------------------------------------------------
-- ĐỒNG BỘ purchase_order_lines.received_qty + status PO TỪ PHIẾU NHẬN ĐÃ GHI SỔ.
-- Tính lại TỪ ĐẦU mỗi lần, nên huỷ/xoá phiếu thì số liệu tự lùi về đúng mức.
-- -----------------------------------------------------------------------------
-- Khoá theo thứ tự CỐ ĐỊNH: PO cha TRƯỚC rồi mới tới dòng. fn_po_sync_totals cũng chỉ khoá
-- PO cha -> mọi đường ghi đều lấy khoá cùng chiều, không deadlock chéo.
CREATE
OR REPLACE FUNCTION fn_recalc_po_line_received (p_po_line_id UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    v_po_id UUID;
BEGIN
    IF p_po_line_id IS NULL THEN
        RETURN; -- dòng nhận trực tiếp, không gắn PO
    END IF;

    SELECT po_id INTO v_po_id FROM purchase_order_lines WHERE id = p_po_line_id;
    IF v_po_id IS NULL THEN
        RETURN; -- dòng PO đã bị xoá
    END IF;

    PERFORM 1 FROM purchase_orders WHERE id = v_po_id FOR UPDATE;

    UPDATE purchase_order_lines l
    SET received_qty = COALESCE(s.qty, 0)
    FROM (SELECT SUM(grl.received_qty_base) AS qty
          FROM goods_receipt_lines grl
                   JOIN goods_receipts gr ON gr.id = grl.gr_id
          WHERE grl.po_line_id = p_po_line_id
            AND gr.status = 'POSTED' -- CHỈ chứng từ đã ghi sổ mới được tính
            AND gr.deleted_at IS NULL) s
    WHERE l.id = p_po_line_id;

    PERFORM fn_recalc_po_status(v_po_id);
END
$$;

-- CONFIRMED <-> PARTIALLY_RECEIVED <-> RECEIVED. KHÔNG đụng DRAFT/CANCELLED: phiếu chưa
-- xác nhận hoặc đã huỷ thì việc nhận hàng không được phép kéo trạng thái của nó đi.
CREATE
OR REPLACE FUNCTION fn_recalc_po_status (p_po_id UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    v_status TEXT;
    v_total  INT;
    v_full   INT;
    v_any    BOOLEAN;
BEGIN
    SELECT status INTO v_status FROM purchase_orders WHERE id = p_po_id;
    IF v_status IS NULL OR v_status IN ('DRAFT', 'CANCELLED') THEN
        RETURN;
    END IF;

    -- received_qty và ordered_qty_base cùng là base UOM nên so sánh trực tiếp được.
    SELECT count(*),
           count(*) FILTER (WHERE received_qty >= ordered_qty_base),
           bool_or(received_qty > 0)
    INTO v_total, v_full, v_any
    FROM purchase_order_lines
    WHERE po_id = p_po_id;

    UPDATE purchase_orders
    SET status = CASE
                     WHEN v_total > 0 AND v_full = v_total THEN 'RECEIVED'
                     WHEN COALESCE(v_any, FALSE) THEN 'PARTIALLY_RECEIVED'
                     ELSE 'CONFIRMED'
        END
    WHERE id = p_po_id;
END
$$;

CREATE
OR REPLACE FUNCTION fn_gr_lines_sync_received () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM fn_recalc_po_line_received(COALESCE(NEW.po_line_id, OLD.po_line_id));

    -- Dòng bị chuyển sang PO line khác: đồng bộ lại cả bên cũ.
    IF TG_OP = 'UPDATE' AND NEW.po_line_id IS DISTINCT FROM OLD.po_line_id THEN
        PERFORM fn_recalc_po_line_received(OLD.po_line_id);
    END IF;

    RETURN NULL;
END
$$;

CREATE TRIGGER trg_gr_lines_sync_received
AFTER INSERT
OR DELETE
OR
UPDATE OF po_line_id,
received_qty,
conversion_factor ON goods_receipt_lines FOR EACH ROW
EXECUTE FUNCTION fn_gr_lines_sync_received ();

-- Vì sao cần trigger thứ hai (ĐỪNG GỠ): số liệu do HAI bảng cùng quyết định —
-- goods_receipt_lines cho số lượng, goods_receipts.status/deleted_at cho việc số đó có được
-- tính hay không. Canh mỗi bảng dòng là để hở: DRAFT -> POSTED không đụng dòng nào mà vẫn
-- lật toàn bộ số đã nhận. Cùng lý do với cặp trg_bom_lines_no_cycle / trg_boms_no_cycle.
CREATE
OR REPLACE FUNCTION fn_gr_sync_received () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT DISTINCT po_line_id
             FROM goods_receipt_lines
             WHERE gr_id = NEW.id
               AND po_line_id IS NOT NULL
        LOOP
            PERFORM fn_recalc_po_line_received(r.po_line_id);
        END LOOP;
    RETURN NULL;
END
$$;

CREATE TRIGGER trg_gr_sync_received
AFTER
UPDATE OF status,
deleted_at ON goods_receipts FOR EACH ROW
EXECUTE FUNCTION fn_gr_sync_received ();

-- -----------------------------------------------------------------------------
-- QUY ĐỔI VỀ ĐƠN VỊ CƠ SỞ (base) CỦA ITEM
-- Trả về HỆ SỐ k sao cho:  qty_base = qty * k.
-- Mọi cột *_base trong hệ đều do trigger gọi hàm này điền — MỌI view/hàm tính ở base.
-- KHÔNG BAO GIỜ trả NULL: đơn vị không quy đổi được thì RAISE, vì NULL sẽ nhân
-- lan qua từng cấp BOM rồi ra kết quả rỗng mà không một cảnh báo nào.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_uom_factor_to_base (p_item_id UUID, p_uom_id UUID) RETURNS NUMERIC LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_base_uom UUID;
    v_factor   NUMERIC;
    v_dim_u    uom_dimension;
    v_ratio_u  NUMERIC;
    v_dim_b    uom_dimension;
    v_ratio_b  NUMERIC;
BEGIN
    SELECT base_uom_id INTO v_base_uom FROM items WHERE id = p_item_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Item % không tồn tại', p_item_id USING ERRCODE = 'UOM01';
    END IF;

    -- CA 1: đã là đơn vị cơ sở.
    IF p_uom_id = v_base_uom THEN
        RETURN 1;
    END IF;

    -- CA 2: quy đổi RIÊNG THEO ITEM — tỷ trọng (cồn lít -> kg), quy cách PACK
    -- (thùng -> cái). Xét TRƯỚC ca 3: cái riêng cho item phải thắng quy tắc chung.
    SELECT factor_to_base
    INTO v_factor
    FROM item_uom_conversions
    WHERE item_id = p_item_id
      AND uom_id = p_uom_id;
    IF FOUND THEN
        RETURN v_factor;
    END IF;

    -- CA 3: cùng dimension -> quy đổi qua đơn vị mốc (g -> kg, ml -> l).
    SELECT dimension, ratio_to_anchor INTO v_dim_u, v_ratio_u FROM uoms WHERE id = p_uom_id;
    SELECT dimension, ratio_to_anchor INTO v_dim_b, v_ratio_b FROM uoms WHERE id = v_base_uom;

    IF v_dim_u IS NOT NULL AND v_dim_u = v_dim_b AND v_dim_u <> 'PACK' THEN
        RETURN v_ratio_u / v_ratio_b;
    END IF;

    RAISE EXCEPTION 'Không quy đổi được đơn vị % sang đơn vị cơ sở của item %',
        COALESCE((SELECT code FROM uoms WHERE id = p_uom_id), p_uom_id::text),
        COALESCE((SELECT code FROM items WHERE id = p_item_id), p_item_id::text)
        USING ERRCODE = 'UOM01',
            HINT = 'Khác dimension hoặc PACK thì phải khai trong item_uom_conversions.';
END
$$;

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

-- =============================================================================
-- BOM / CÔNG THỨC (đa cấp: component có thể là bán thành phẩm có BOM riêng)
-- =============================================================================
CREATE TYPE bom_status AS ENUM('DRAFT', 'ACTIVE', 'OBSOLETE');

CREATE TABLE
    boms (
        id UUID NOT NULL DEFAULT uuidv7 (),
        item_id UUID NOT NULL, -- thành phẩm / bán thành phẩm công thức này tạo ra
        version VARCHAR(20) NOT NULL,
        output_uom_id UUID NOT NULL,
        status bom_status NOT NULL DEFAULT 'DRAFT', -- ACTIVE = ĐÃ DUYỆT + ĐÃ XẾP LỊCH (xem chk hiệu lực bên dưới)
        output_qty NUMERIC(18, 4) NOT NULL DEFAULT 1 CHECK (output_qty > 0), -- số QUY CHIẾU ("công thức cho 100kg"); MO tự scale
        output_qty_base NUMERIC(18, 6) NOT NULL, -- quy về base item — trg_boms_fill_base tự điền
        yield_rate NUMERIC(5, 4) NOT NULL DEFAULT 1 CHECK (
            yield_rate > 0
            AND yield_rate <= 1
        ), -- hiệu suất MẺ: 0.97 = thu được 97% (bám bồn, sót ống)
        effective_from DATE, -- NULL = vô hạn về quá khứ
        effective_to DATE, -- NULL = chưa biết ngày hết hiệu lực
        note TEXT,
        created_by UUID,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_boms PRIMARY KEY (id),
        -- from = to với '[)' cho ra khoảng RỖNG, mà rỗng không giao với gì nên EXCLUDE
        -- bên dưới KHÔNG bắt được -> phải chặn riêng, nếu không tạo được BOM vô nghĩa.
        CONSTRAINT chk_boms_period CHECK (
            effective_from IS NULL
            OR effective_to IS NULL
            OR effective_to > effective_from
        )
    );

-- HIỆU LỰC THEO THỜI GIAN (thay cho "mỗi item tối đa 1 công thức ACTIVE"):
--   cấm hai BOM ACTIVE cùng item mà khoảng ngày GIAO NHAU. NULL = vô hạn, nên
--   (NULL,NULL) là "mãi mãi" và sẽ đụng mọi khoảng khác của cùng item.
--   '[)' = đóng đầu, mở cuối -> ghi được BOM cũ to='2026-10-01' và BOM mới
--   from='2026-10-01' mà KHÔNG hở ngày nào cũng KHÔNG chồng ngày nào.
ALTER TABLE boms
ADD CONSTRAINT ex_boms_active_period EXCLUDE USING gist (
    item_id
    WITH
        =,
        daterange (effective_from, effective_to, '[)')
    WITH
        &&
)
WHERE
    (status = 'ACTIVE');

CREATE UNIQUE INDEX uidx_boms_item_id_version ON boms (item_id, version);

CREATE INDEX idx_bom_item ON boms (item_id);

CREATE TABLE
    bom_lines (
        id UUID NOT NULL DEFAULT uuidv7 (),
        bom_id UUID NOT NULL,
        line_no SMALLINT NOT NULL, -- thứ tự dòng; trg_bom_lines_fill_line_no tự điền nếu bỏ trống
        component_item_id UUID NOT NULL, -- NVL hoặc bán thành phẩm
        qty NUMERIC(18, 6) NOT NULL CHECK (qty > 0), -- định mức cho output_qty (ở đơn vị uom_id)
        uom_id UUID NOT NULL,
        qty_base NUMERIC(18, 6) NOT NULL, -- quy về base component — trg_bom_lines_fill_base tự điền
        -- TỶ LỆ 0..1, KHÔNG phải phần trăm: 0.05 = hao 5%.
        -- Gross-up:  can_xuat = qty_base / (1 - scrap_rate)
        -- Dùng phép CHIA vì hao hụt xảy ra TRÊN LƯỢNG ĐÃ XUẤT, không phải trên lượng lý
        -- thuyết: cần 100kg hao 5% -> xuất 100/0.95 = 105.263, hao 5.263, còn đúng 100.
        -- (100*1.05 = 105 thì hao 5.25, chỉ còn 99.75 -> thiếu.)
        -- CHECK < 1 là BẮT BUỘC: = 1 làm mẫu số bằng 0.
        scrap_rate NUMERIC(5, 4) NOT NULL DEFAULT 0 CHECK (
            scrap_rate >= 0
            AND scrap_rate < 1
        ),
        note TEXT,
        CONSTRAINT pk_bom_lines PRIMARY KEY (id),
        -- KHÔNG unique theo component: một nguyên liệu được phép xuất hiện nhiều dòng
        -- (nước RO vào pha A rồi lại vào pha C) — gộp lại là mất thông tin cho lúc nào.
        CONSTRAINT uq_bom_lines UNIQUE (bom_id, line_no)
    );

CREATE INDEX idx_bomline_bom ON bom_lines (bom_id);

CREATE INDEX idx_bomline_component ON bom_lines (component_item_id);

-- -----------------------------------------------------------------------------
-- CHỐNG CHU TRÌNH BOM (xem docs/ERP/PRODUCTION.md)
-- Gồm cả ca tự tham chiếu (component = chính item của BOM) — đó là vòng cấp 0.
-- KHÔNG dùng CHECK constraint được vì phải đọc sang bảng khác (boms).
-- Một dòng vòng đủ làm mọi WITH RECURSIVE chạy vô hạn -> đây là ràng buộc toàn
-- vẹn cùng nhóm với FK, không phải "validate form".
-- -----------------------------------------------------------------------------
-- LÕI: khẳng định cạnh (p_parent -> p_component) không khép thành chu trình.
-- Dùng chung cho CẢ HAI trigger bên dưới — cạnh đồ thị BOM do bom_lines VÀ boms
-- cùng quyết định, nên chỉ canh một bảng là để hở (xem 'Vì sao có trg_boms_no_cycle').
CREATE
OR REPLACE FUNCTION fn_assert_no_bom_cycle (p_parent UUID, p_component UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    v_trail UUID[];
    v_codes TEXT;
BEGIN
    -- Có vòng <=> từ component đi xuống quay lại được p_parent.
    -- CYCLE lo việc DỪNG (không bỏ sót ở bất kỳ độ sâu nào, khác hẳn cap lvl < 20);
    -- trail là mảng uuid tự tích luỹ để dựng thông báo — KHÔNG dùng cột path của
    -- CYCLE vì nó là mảng ROW(item_id), không phải uuid[].
    WITH RECURSIVE down AS (SELECT p_component             AS item_id,
                                   ARRAY [p_component]     AS trail
                            UNION ALL
                            SELECT bl.component_item_id,
                                   d.trail || bl.component_item_id
                            FROM down d
                                     JOIN boms b ON b.item_id = d.item_id
                                AND b.status <> 'OBSOLETE'
                                     JOIN bom_lines bl ON bl.bom_id = b.id)
        CYCLE item_id SET is_cycle USING path
    SELECT trail
    INTO v_trail
    FROM down
    WHERE item_id = p_parent
    LIMIT 1;

    IF v_trail IS NOT NULL THEN
        SELECT string_agg(i.code, ' -> ' ORDER BY p.ord)
        INTO v_codes
        FROM unnest(array_prepend(p_parent, v_trail)) WITH ORDINALITY AS p(item_id, ord)
                 JOIN items i ON i.id = p.item_id;

        RAISE EXCEPTION 'Công thức tạo chu trình: %', v_codes
            USING ERRCODE = 'BOM01',
                HINT = 'Một item không được chứa chính nó ở cấp dưới.';
    END IF;
END
$$;

CREATE
OR REPLACE FUNCTION fn_check_bom_cycle () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    v_parent UUID;
BEGIN
    -- Tuần tự hoá mọi thao tác ghi đồ thị BOM. KHÔNG gỡ dòng này: ở READ COMMITTED,
    -- hai transaction song song thêm A->B và B->A đều không thấy dòng chưa commit
    -- của bên kia nên cả hai đều báo "sạch" rồi tạo ra vòng. Xem docs/ERP/PRODUCTION.md.
    PERFORM pg_advisory_xact_lock(hashtext('bom_graph'));

    -- Trigger là AFTER nên dòng NEW đã nằm trong bảng, đệ quy tự tính cả cạnh mới.
    SELECT item_id INTO v_parent FROM boms WHERE id = NEW.bom_id;
    PERFORM fn_assert_no_bom_cycle(v_parent, NEW.component_item_id);
    RETURN NULL;
END
$$;

-- Vì sao có trg_boms_no_cycle (ĐỪNG GỠ):
--   Cạnh đồ thị không chỉ do bom_lines quyết định. boms.item_id nói cạnh thuộc item
--   nào, còn boms.status là CHÍNH bộ lọc 'status <> OBSOLETE' mà phép quét dùng.
--   Thiếu trigger này thì lách được bằng UPDATE hợp lệ, không cần DISABLE TRIGGER:
--     BOM của X đang OBSOLETE chứa X->Y  ->  thêm Y->X (hợp lệ, chưa có vòng)
--     ->  UPDATE boms SET status='ACTIVE' cho BOM của X  ->  vòng X->Y->X xuất hiện.
--   Kiểm từng cạnh của BOM là đủ: mọi chu trình đi qua BOM này phải dùng ít nhất
--   một cạnh của nó.
CREATE
OR REPLACE FUNCTION fn_check_boms_cycle () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    r RECORD;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('bom_graph'));

    -- Chuyển sang OBSOLETE là BỚT cạnh -> không thể sinh vòng, khỏi quét.
    IF NEW.status = 'OBSOLETE' THEN
        RETURN NULL;
    END IF;

    FOR r IN SELECT component_item_id FROM bom_lines WHERE bom_id = NEW.id
        LOOP
            PERFORM fn_assert_no_bom_cycle(NEW.item_id, r.component_item_id);
        END LOOP;
    RETURN NULL;
END
$$;

-- status <> 'OBSOLETE' trong phép quét: duyệt cả DRAFT lẫn ACTIVE, nếu không người
--   dùng dựng được vòng ở DRAFT rồi kích hoạt sau.
-- AFTER: để dòng mới đã có mặt trong bảng, đệ quy không phải xử lý riêng cạnh mới.
-- UPDATE OF (...): chỉ chạy lại khi CẠNH đồ thị đổi, sửa qty/scrap_rate không kích hoạt.
-- ERRCODE 'BOM01': app bắt theo mã, không so khớp chuỗi thông báo.
CREATE TRIGGER trg_bom_lines_no_cycle
AFTER INSERT
OR
UPDATE OF bom_id,
component_item_id ON bom_lines FOR EACH ROW
EXECUTE FUNCTION fn_check_bom_cycle ();

-- Không cần cho INSERT: BOM mới chưa có dòng nào, dòng thêm sau đã có trigger trên.
CREATE TRIGGER trg_boms_no_cycle
AFTER
UPDATE OF item_id,
status ON boms FOR EACH ROW
EXECUTE FUNCTION fn_check_boms_cycle ();

-- -----------------------------------------------------------------------------
-- ĐIỀN CỘT *_base (quy đổi đơn vị) — mọi view/hàm tính ở base.
-- BEFORE nên chạy TRƯỚC khi kiểm NOT NULL của output_qty_base/qty_base.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_fill_boms_base () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.output_qty_base := NEW.output_qty * fn_uom_factor_to_base(NEW.item_id, NEW.output_uom_id);
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_boms_fill_base BEFORE INSERT
OR
UPDATE OF item_id,
output_uom_id,
output_qty ON boms FOR EACH ROW
EXECUTE FUNCTION fn_fill_boms_base ();

CREATE
OR REPLACE FUNCTION fn_fill_bom_lines_base () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.qty_base := NEW.qty * fn_uom_factor_to_base(NEW.component_item_id, NEW.uom_id);
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_bom_lines_fill_base BEFORE INSERT
OR
UPDATE OF component_item_id,
uom_id,
qty ON bom_lines FOR EACH ROW
EXECUTE FUNCTION fn_fill_bom_lines_base ();

-- -----------------------------------------------------------------------------
-- Tự đánh số thứ tự dòng khi không truyền line_no.
-- Ghi chú đồng thời: hai transaction cùng chèn vào MỘT bom có thể cùng tính ra
-- max+1; uq_bom_lines sẽ chặn và một bên nhận lỗi trùng khoá. Chấp nhận được —
-- sửa công thức là hành vi hiếm, và đó là lỗi sạch chứ không phải hỏng dữ liệu.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_fill_bom_line_no () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.line_no IS NULL THEN
        SELECT COALESCE(MAX(line_no), 0) + 1 INTO NEW.line_no
        FROM bom_lines
        WHERE bom_id = NEW.bom_id;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_bom_lines_fill_line_no BEFORE INSERT ON bom_lines FOR EACH ROW
EXECUTE FUNCTION fn_fill_bom_line_no ();

-- -----------------------------------------------------------------------------
-- CÔNG THỨC ĐANG CÓ HIỆU LỰC
-- Sau khi có lịch, status và HIỆU LỰC là hai chuyện khác nhau:
--   status = 'ACTIVE'  ->  "đã duyệt + đã xếp lịch", KHÔNG còn nghĩa "đang dùng"
--   đang dùng          ->  ACTIVE **và** ngày đang xét nằm trong khoảng hiệu lực
-- MỌI chỗ nổ BOM / chạy MRP / tra định mức PHẢI dùng fn_bom_in_force, KHÔNG dùng
-- WHERE status='ACTIVE' — quên là lấy nhầm công thức xếp lịch cho tháng sau.
-- Truyền p_date để dựng lại đúng công thức đã dùng cho một lệnh SX cũ.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_bom_in_force (p_item_id UUID, p_date DATE DEFAULT CURRENT_DATE) RETURNS UUID LANGUAGE sql STABLE AS $$
SELECT b.id
FROM boms b
WHERE b.item_id = p_item_id
  AND b.status = 'ACTIVE'
  AND daterange(b.effective_from, b.effective_to, '[)') @> p_date;
$$;

-- =============================================================================
-- TRIGGER: CHUYỂN KHO / XUẤT KHO / KIỂM KÊ / SẢN XUẤT
-- Đặt sau BOM vì fn_mo_explode_bom cần fn_bom_in_force và bom_lines.
-- =============================================================================
--- Tự sinh số chứng từ, cùng khuôn fn_po_fill_number / fn_gr_fill_number.
CREATE
OR REPLACE FUNCTION fn_st_fill_number () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.transfer_number IS NULL THEN NEW.transfer_number := fn_next_doc_number('ST'); END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_st_fill_number BEFORE INSERT ON stock_transfers FOR EACH ROW
EXECUTE FUNCTION fn_st_fill_number ();

CREATE
OR REPLACE FUNCTION fn_si_fill_number () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.issue_number IS NULL THEN NEW.issue_number := fn_next_doc_number('SI'); END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_si_fill_number BEFORE INSERT ON stock_issues FOR EACH ROW
EXECUTE FUNCTION fn_si_fill_number ();

CREATE
OR REPLACE FUNCTION fn_sa_fill_number () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.adjustment_number IS NULL THEN NEW.adjustment_number := fn_next_doc_number('SA'); END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_sa_fill_number BEFORE INSERT ON stock_adjustments FOR EACH ROW
EXECUTE FUNCTION fn_sa_fill_number ();

CREATE
OR REPLACE FUNCTION fn_mo_fill_number () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.mo_number IS NULL THEN NEW.mo_number := fn_next_doc_number('MO'); END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_mo_fill_number BEFORE INSERT ON manufacturing_orders FOR EACH ROW
EXECUTE FUNCTION fn_mo_fill_number ();

CREATE
OR REPLACE FUNCTION fn_pr_fill_number () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.pr_number IS NULL THEN NEW.pr_number := fn_next_doc_number('PR'); END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_pr_fill_number BEFORE INSERT ON production_receipts FOR EACH ROW
EXECUTE FUNCTION fn_pr_fill_number ();

--- Quy tắc chứng từ dùng chung, gắn cho các bảng mới.
CREATE TRIGGER trg_stl_frozen BEFORE INSERT
OR
UPDATE
OR DELETE ON stock_transfer_lines FOR EACH ROW
EXECUTE FUNCTION fn_doc_lines_frozen ('stock_transfers', 'transfer_id');

CREATE TRIGGER trg_st_status_flow BEFORE
UPDATE OF status ON stock_transfers FOR EACH ROW
EXECUTE FUNCTION fn_doc_status_flow ();

CREATE TRIGGER trg_sil_frozen BEFORE INSERT
OR
UPDATE
OR DELETE ON stock_issue_lines FOR EACH ROW
EXECUTE FUNCTION fn_doc_lines_frozen ('stock_issues', 'issue_id');

CREATE TRIGGER trg_si_status_flow BEFORE
UPDATE OF status ON stock_issues FOR EACH ROW
EXECUTE FUNCTION fn_doc_status_flow ();

CREATE TRIGGER trg_sal_frozen BEFORE INSERT
OR
UPDATE
OR DELETE ON stock_adjustment_lines FOR EACH ROW
EXECUTE FUNCTION fn_doc_lines_frozen ('stock_adjustments', 'adjustment_id');

CREATE TRIGGER trg_sa_status_flow BEFORE
UPDATE OF status ON stock_adjustments FOR EACH ROW
EXECUTE FUNCTION fn_doc_status_flow ();

CREATE TRIGGER trg_pr_status_flow BEFORE
UPDATE OF status ON production_receipts FOR EACH ROW
EXECUTE FUNCTION fn_doc_status_flow ();

-- production_receipts là bảng PHẲNG nên không có *_lines để khoá — phải tự khoá chính nó,
-- nếu không sửa qty của phiếu đã POSTED sẽ làm sổ lệch vĩnh viễn.
CREATE
OR REPLACE FUNCTION fn_pr_frozen () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status <> 'DRAFT'
        AND (NEW.item_id, NEW.lot_id, NEW.storage_bin_id, NEW.qty_base, NEW.unit_cost_vnd)
            IS DISTINCT FROM
            (OLD.item_id, OLD.lot_id, OLD.storage_bin_id, OLD.qty_base, OLD.unit_cost_vnd) THEN
        RAISE EXCEPTION 'Phiếu nhập thành phẩm đã ở trạng thái % — không sửa được số liệu', OLD.status
            USING ERRCODE = 'DOC01';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_pr_frozen BEFORE
UPDATE ON production_receipts FOR EACH ROW
EXECUTE FUNCTION fn_pr_frozen ();

-- -----------------------------------------------------------------------------
-- GHI SỔ: CHUYỂN KHO. Mỗi dòng đẻ HAI bút toán. Giá vốn giữ nguyên — đổi chỗ không đổi giá,
-- nên lấy giá vốn bình quân đang có ở bin đi.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_st_post_to_ledger () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    r         RECORD;
    v_cost    NUMERIC;
    v_sign    NUMERIC;
BEGIN
    IF NEW.status = 'POSTED' THEN
        v_sign := 1;
    ELSIF NEW.status = 'CANCELLED' AND OLD.status = 'POSTED' THEN
        v_sign := -1; -- bút toán đảo: OUT thành nhập lại, IN thành xuất ra
    ELSE
        RETURN NULL;
    END IF;

    FOR r IN SELECT * FROM stock_transfer_lines WHERE transfer_id = NEW.id
        LOOP
            -- Chiều bị trừ tồn phải kiểm đủ: POSTED trừ ở from_bin, CANCELLED trừ ở to_bin.
            IF v_sign = 1 THEN
                PERFORM fn_assert_stock_available(r.item_id, r.lot_id, r.from_bin_id, r.qty_base);
            ELSE
                PERFORM fn_assert_stock_available(r.item_id, r.lot_id, r.to_bin_id, r.qty_base);
            END IF;

            SELECT AVG(unit_cost_vnd) INTO v_cost
            FROM inventory_movements
            WHERE item_id = r.item_id
              AND lot_id IS NOT DISTINCT FROM r.lot_id
              AND unit_cost_vnd IS NOT NULL;

            INSERT INTO inventory_movements (movement_type, movement_at, item_id, lot_id,
                                             storage_bin_id, qty_base, unit_cost_vnd,
                                             transfer_line_id, created_by)
            VALUES ('TRANSFER_OUT', COALESCE(NEW.posted_at, NOW()), r.item_id, r.lot_id,
                    r.from_bin_id, -r.qty_base * v_sign, v_cost, r.id, NEW.transferred_by),
                   ('TRANSFER_IN', COALESCE(NEW.posted_at, NOW()), r.item_id, r.lot_id,
                    r.to_bin_id, r.qty_base * v_sign, v_cost, r.id, NEW.transferred_by);
        END LOOP;
    RETURN NULL;
END
$$;

CREATE TRIGGER trg_st_post_to_ledger
AFTER
UPDATE OF status ON stock_transfers FOR EACH ROW WHEN (
    OLD.status IS DISTINCT
    FROM
        NEW.status
)
EXECUTE FUNCTION fn_st_post_to_ledger ();

-- -----------------------------------------------------------------------------
-- GHI SỔ: XUẤT KHO. movement_type suy từ issue_type.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_si_post_to_ledger () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    r       RECORD;
    v_type  movement_type;
    v_sign  NUMERIC;
    v_cost  NUMERIC;
BEGIN
    IF NEW.status = 'POSTED' THEN
        v_sign := -1;
    ELSIF NEW.status = 'CANCELLED' AND OLD.status = 'POSTED' THEN
        v_sign := 1; -- đảo: trả hàng về kho
    ELSE
        RETURN NULL;
    END IF;

    v_type := CASE NEW.issue_type
                  WHEN 'RETURN_VENDOR' THEN 'RETURN_OUT'
                  WHEN 'SCRAP' THEN 'SCRAP'
                  ELSE 'ISSUE'
        END::movement_type;

    FOR r IN SELECT * FROM stock_issue_lines WHERE issue_id = NEW.id
        LOOP
            IF v_sign = -1 THEN
                PERFORM fn_assert_stock_available(r.item_id, r.lot_id, r.storage_bin_id, r.qty_base);
            END IF;

            SELECT AVG(unit_cost_vnd) INTO v_cost
            FROM inventory_movements
            WHERE item_id = r.item_id
              AND lot_id IS NOT DISTINCT FROM r.lot_id
              AND unit_cost_vnd IS NOT NULL;

            INSERT INTO inventory_movements (movement_type, movement_at, item_id, lot_id,
                                             storage_bin_id, qty_base, unit_cost_vnd,
                                             issue_line_id, created_by)
            VALUES (v_type, COALESCE(NEW.posted_at, NOW()), r.item_id, r.lot_id,
                    r.storage_bin_id, r.qty_base * v_sign, v_cost, r.id, NEW.issued_by);
        END LOOP;

    PERFORM fn_recalc_mo_issued(NEW.mo_id);
    RETURN NULL;
END
$$;

CREATE TRIGGER trg_si_post_to_ledger
AFTER
UPDATE OF status ON stock_issues FOR EACH ROW WHEN (
    OLD.status IS DISTINCT
    FROM
        NEW.status
)
EXECUTE FUNCTION fn_si_post_to_ledger ();

-- -----------------------------------------------------------------------------
-- GHI SỔ: KIỂM KÊ. Chênh lệch đếm-thực trừ tồn-sổ là bút toán ADJUSTMENT (dương hoặc âm).
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_sa_post_to_ledger () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    r      RECORD;
    v_sign NUMERIC;
    v_cost NUMERIC;
BEGIN
    IF NEW.status = 'POSTED' THEN
        v_sign := 1;
    ELSIF NEW.status = 'CANCELLED' AND OLD.status = 'POSTED' THEN
        v_sign := -1;
    ELSE
        RETURN NULL;
    END IF;

    FOR r IN SELECT * FROM stock_adjustment_lines WHERE adjustment_id = NEW.id AND diff_qty_base <> 0
        LOOP
            IF r.diff_qty_base * v_sign < 0 THEN
                PERFORM fn_assert_stock_available(r.item_id, r.lot_id, r.storage_bin_id,
                                                  -r.diff_qty_base * v_sign);
            END IF;

            SELECT AVG(unit_cost_vnd) INTO v_cost
            FROM inventory_movements
            WHERE item_id = r.item_id
              AND lot_id IS NOT DISTINCT FROM r.lot_id
              AND unit_cost_vnd IS NOT NULL;

            INSERT INTO inventory_movements (movement_type, movement_at, item_id, lot_id,
                                             storage_bin_id, qty_base, unit_cost_vnd,
                                             adjustment_line_id, created_by)
            VALUES ('ADJUSTMENT', COALESCE(NEW.posted_at, NOW()), r.item_id, r.lot_id,
                    r.storage_bin_id, r.diff_qty_base * v_sign, v_cost, r.id, NEW.counted_by);
        END LOOP;
    RETURN NULL;
END
$$;

CREATE TRIGGER trg_sa_post_to_ledger
AFTER
UPDATE OF status ON stock_adjustments FOR EACH ROW WHEN (
    OLD.status IS DISTINCT
    FROM
        NEW.status
)
EXECUTE FUNCTION fn_sa_post_to_ledger ();

-- -----------------------------------------------------------------------------
-- NỔ ĐỊNH MỨC KHI TẠO LỆNH SẢN XUẤT.
-- Gộp cả hai loại hao, và chúng KHÁC nhau:
--   yield_rate  = hao MẺ (bám bồn, sót ống) -> phải chạy mẻ to hơn: planned / yield_rate
--   scrap_rate  = hao TRÊN LƯỢNG ĐÃ XUẤT     -> phải xuất nhiều hơn: qty / (1 - scrap_rate)
-- Kiểm nhanh: BOM 100kg, yield 0.97, dòng 10kg, scrap 0.05, MO 200kg -> 21.7kg.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_mo_explode_bom () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    v_scale NUMERIC;
BEGIN
    SELECT (NEW.planned_qty_base / b.yield_rate) / b.output_qty_base
    INTO v_scale
    FROM boms b
    WHERE b.id = NEW.bom_id;

    IF v_scale IS NULL THEN
        RAISE EXCEPTION 'Không tìm thấy công thức % cho lệnh sản xuất', NEW.bom_id
            USING ERRCODE = 'MO001';
    END IF;

    INSERT INTO mo_material_lines (mo_id, component_item_id, required_qty_base, line_no)
    SELECT NEW.id,
           bl.component_item_id,
           bl.qty_base * v_scale / (1 - bl.scrap_rate),
           bl.line_no
    FROM bom_lines bl
    WHERE bl.bom_id = NEW.bom_id;

    RETURN NULL;
END
$$;

CREATE TRIGGER trg_mo_explode_bom
AFTER INSERT ON manufacturing_orders FOR EACH ROW
EXECUTE FUNCTION fn_mo_explode_bom ();

-- -----------------------------------------------------------------------------
-- ĐỒNG BỘ NGƯỢC VỀ LỆNH SẢN XUẤT — recalc-from-scratch, khoá cha trước (cùng khuôn
-- fn_recalc_po_line_received), nên huỷ phiếu thì số liệu tự lùi về đúng mức.
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_recalc_mo_issued (p_mo_id UUID) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    IF p_mo_id IS NULL THEN RETURN; END IF;
    PERFORM 1 FROM manufacturing_orders WHERE id = p_mo_id FOR UPDATE;

    UPDATE mo_material_lines m
    SET issued_qty_base = COALESCE(s.qty, 0)
    FROM (SELECT sil.item_id, SUM(sil.qty_base) AS qty
          FROM stock_issue_lines sil
                   JOIN stock_issues si ON si.id = sil.issue_id
          WHERE si.mo_id = p_mo_id
            AND si.status = 'POSTED'
            AND si.deleted_at IS NULL
          GROUP BY sil.item_id) s
    WHERE m.mo_id = p_mo_id AND m.component_item_id = s.item_id;

    -- Thành phần chưa xuất dòng nào (hoặc phiếu vừa bị huỷ) phải về 0.
    UPDATE mo_material_lines m
    SET issued_qty_base = 0
    WHERE m.mo_id = p_mo_id
      AND NOT EXISTS (SELECT 1
                      FROM stock_issue_lines sil
                               JOIN stock_issues si ON si.id = sil.issue_id
                      WHERE si.mo_id = p_mo_id AND si.status = 'POSTED'
                        AND si.deleted_at IS NULL AND sil.item_id = m.component_item_id);

    PERFORM fn_recalc_mo_status(p_mo_id);
END
$$;

CREATE
OR REPLACE FUNCTION fn_recalc_mo_status (p_mo_id UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    v_status   mo_status;
    v_planned  NUMERIC;
    v_produced NUMERIC;
    v_issued   BOOLEAN;
BEGIN
    SELECT status, planned_qty_base, produced_qty_base
    INTO v_status, v_planned, v_produced
    FROM manufacturing_orders WHERE id = p_mo_id;

    -- DRAFT chưa phát lệnh, CANCELLED/COMPLETED đã chốt -> không tự động kéo đi.
    IF v_status IS NULL OR v_status IN ('DRAFT', 'CANCELLED') THEN RETURN; END IF;

    SELECT bool_or(issued_qty_base > 0) INTO v_issued
    FROM mo_material_lines WHERE mo_id = p_mo_id;

    UPDATE manufacturing_orders
    SET status = CASE
                     WHEN v_produced >= v_planned THEN 'COMPLETED'
                     WHEN COALESCE(v_issued, FALSE) THEN 'IN_PROGRESS'
                     ELSE 'RELEASED'
        END::mo_status,
        actual_end = CASE WHEN v_produced >= v_planned THEN COALESCE(actual_end, NOW()) END,
        actual_start = CASE WHEN COALESCE(v_issued, FALSE) THEN COALESCE(actual_start, NOW()) END
    WHERE id = p_mo_id;
END
$$;

-- -----------------------------------------------------------------------------
-- GHI SỔ: NHẬP THÀNH PHẨM (bảng phẳng, mỗi dòng một bút toán PRODUCTION_IN).
-- -----------------------------------------------------------------------------
CREATE
OR REPLACE FUNCTION fn_pr_post_to_ledger () RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    v_sign NUMERIC;
BEGIN
    IF NEW.status = 'POSTED' THEN
        v_sign := 1;
    ELSIF NEW.status = 'CANCELLED' AND OLD.status = 'POSTED' THEN
        v_sign := -1;
        PERFORM fn_assert_stock_available(NEW.item_id, NEW.lot_id, NEW.storage_bin_id, NEW.qty_base);
    ELSE
        RETURN NULL;
    END IF;

    INSERT INTO inventory_movements (movement_type, movement_at, item_id, lot_id,
                                     storage_bin_id, qty_base, unit_cost_vnd,
                                     production_receipt_id, created_by)
    VALUES ('PRODUCTION_IN', COALESCE(NEW.posted_at, NOW()), NEW.item_id, NEW.lot_id,
            NEW.storage_bin_id, NEW.qty_base * v_sign, NEW.unit_cost_vnd, NEW.id, NEW.received_by);

    PERFORM fn_recalc_mo_produced(NEW.mo_id);
    RETURN NULL;
END
$$;

CREATE TRIGGER trg_pr_post_to_ledger
AFTER
UPDATE OF status ON production_receipts FOR EACH ROW WHEN (
    OLD.status IS DISTINCT
    FROM
        NEW.status
)
EXECUTE FUNCTION fn_pr_post_to_ledger ();

CREATE
OR REPLACE FUNCTION fn_recalc_mo_produced (p_mo_id UUID) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    IF p_mo_id IS NULL THEN RETURN; END IF;
    PERFORM 1 FROM manufacturing_orders WHERE id = p_mo_id FOR UPDATE;

    UPDATE manufacturing_orders mo
    SET produced_qty_base = COALESCE((SELECT SUM(pr.qty_base)
                                      FROM production_receipts pr
                                      WHERE pr.mo_id = p_mo_id
                                        AND pr.status = 'POSTED'
                                        AND pr.deleted_at IS NULL), 0)
    WHERE mo.id = p_mo_id;

    PERFORM fn_recalc_mo_status(p_mo_id);
END
$$;

-- ==========================================================
-- Khoá ngoại
-- ==========================================================
--- AddForeignKey password_tokens table
ALTER TABLE password_tokens
ADD CONSTRAINT fk_password_tokens_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

--- AddForeignKey user_sessions table
ALTER TABLE user_sessions
ADD CONSTRAINT fk_user_sessions_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

-- AddForeignKey role_permissions table
ALTER TABLE role_permissions
ADD CONSTRAINT fk_role_permissions_role_id FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE role_permissions
ADD CONSTRAINT fk_role_permissions_permission_id FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey user_roles table
ALTER TABLE user_roles
ADD CONSTRAINT fk_user_roles_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE user_roles
ADD CONSTRAINT fk_user_roles_role_id FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey items table
ALTER TABLE items
ADD CONSTRAINT fk_items_base_uom_id FOREIGN KEY (base_uom_id) REFERENCES uoms (id) ON DELETE RESTRICT;

-- AddForeignKey item_uom_conversion table
ALTER TABLE item_uom_conversions
ADD CONSTRAINT fk_item_uom_conversions_item_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE CASCADE;

ALTER TABLE item_uom_conversions
ADD CONSTRAINT fk_item_uom_conversions_item_uom_id FOREIGN KEY (uom_id) REFERENCES uoms (id);

-- AddForeignKey warehouse_zones table
ALTER TABLE warehouse_zones
ADD CONSTRAINT fk_warehouse_zones_location_id FOREIGN KEY (location_id) REFERENCES locations (id);

-- AddForeignKey warehouse_zones table
ALTER TABLE storage_bins
ADD CONSTRAINT fk_storage_bins_zone_id FOREIGN KEY (zone_id) REFERENCES warehouse_zones (id);

-- AddForeignKey boms table
ALTER TABLE boms
ADD CONSTRAINT fk_boms_item_id FOREIGN KEY (item_id) REFERENCES items (id);

ALTER TABLE boms
ADD CONSTRAINT fk_boms_output_uom_id FOREIGN KEY (output_uom_id) REFERENCES uoms (id);

ALTER TABLE boms
ADD CONSTRAINT fk_boms_created_by FOREIGN KEY (created_by) REFERENCES users (id);

-- AddForeignKey boms table
ALTER TABLE bom_lines
ADD CONSTRAINT fk_bom_lines_bom_id FOREIGN KEY (bom_id) REFERENCES boms (id) ON DELETE CASCADE;

ALTER TABLE bom_lines
ADD CONSTRAINT fk_bom_lines_component_item_id FOREIGN KEY (component_item_id) REFERENCES items (id);

ALTER TABLE bom_lines
ADD CONSTRAINT fk_bom_lines_uom_id FOREIGN KEY (uom_id) REFERENCES uoms (id);

-- AddForeignKey vendor_items table
ALTER TABLE vendor_items
ADD CONSTRAINT fk_vendor_items_vendor_id FOREIGN KEY (vendor_id) REFERENCES vendors (id) ON DELETE CASCADE;

ALTER TABLE vendor_items
ADD CONSTRAINT fk_vendor_items_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

-- AddForeignKey purchase_orders table
ALTER TABLE purchase_orders
ADD CONSTRAINT fk_purchase_orders_vendor_id FOREIGN KEY (vendor_id) REFERENCES vendors (id) ON DELETE RESTRICT;

ALTER TABLE purchase_orders
ADD CONSTRAINT fk_purchase_orders_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT;

-- AddForeignKey purchase_order_lines table
ALTER TABLE purchase_order_lines
ADD CONSTRAINT fk_purchase_order_lines_po_id FOREIGN KEY (po_id) REFERENCES purchase_orders (id) ON DELETE CASCADE;

ALTER TABLE purchase_order_lines
ADD CONSTRAINT fk_purchase_order_lines_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

-- AddForeignKey lots table
ALTER TABLE lots
ADD CONSTRAINT fk_lots_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

-- AddForeignKey goods_receipts table
ALTER TABLE goods_receipts
ADD CONSTRAINT fk_goods_receipts_vendor_id FOREIGN KEY (vendor_id) REFERENCES vendors (id) ON DELETE RESTRICT;

ALTER TABLE goods_receipts
ADD CONSTRAINT fk_goods_receipts_received_by FOREIGN KEY (received_by) REFERENCES users (id) ON DELETE RESTRICT;

-- AddForeignKey goods_receipt_lines table
ALTER TABLE goods_receipt_lines
ADD CONSTRAINT fk_goods_receipt_lines_gr_id FOREIGN KEY (gr_id) REFERENCES goods_receipts (id) ON DELETE CASCADE;

ALTER TABLE goods_receipt_lines
ADD CONSTRAINT fk_goods_receipt_lines_po_line_id FOREIGN KEY (po_line_id) REFERENCES purchase_order_lines (id) ON DELETE RESTRICT;

ALTER TABLE goods_receipt_lines
ADD CONSTRAINT fk_goods_receipt_lines_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

ALTER TABLE goods_receipt_lines
ADD CONSTRAINT fk_goods_receipt_lines_lot_id FOREIGN KEY (lot_id) REFERENCES lots (id) ON DELETE RESTRICT;

ALTER TABLE goods_receipt_lines
ADD CONSTRAINT fk_goods_receipt_lines_storage_bin_id FOREIGN KEY (storage_bin_id) REFERENCES storage_bins (id) ON DELETE RESTRICT;

-- AddForeignKey vendor_invoices table
ALTER TABLE vendor_invoices
ADD CONSTRAINT fk_vendor_invoices_vendor_id FOREIGN KEY (vendor_id) REFERENCES vendors (id) ON DELETE RESTRICT;

-- AddForeignKey vendor_invoice_lines table
ALTER TABLE vendor_invoice_lines
ADD CONSTRAINT fk_vendor_invoice_lines_invoice_id FOREIGN KEY (invoice_id) REFERENCES vendor_invoices (id) ON DELETE CASCADE;

ALTER TABLE vendor_invoice_lines
ADD CONSTRAINT fk_vendor_invoice_lines_gr_line_id FOREIGN KEY (gr_line_id) REFERENCES goods_receipt_lines (id) ON DELETE RESTRICT;

ALTER TABLE vendor_invoice_lines
ADD CONSTRAINT fk_vendor_invoice_lines_po_line_id FOREIGN KEY (po_line_id) REFERENCES purchase_order_lines (id) ON DELETE RESTRICT;

ALTER TABLE vendor_invoice_lines
ADD CONSTRAINT fk_vendor_invoice_lines_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

-- AddForeignKey inventory_movements table
-- TẤT CẢ đều RESTRICT, KHÔNG CASCADE: sổ kế toán không được biến mất theo chứng từ.
ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_lot_id FOREIGN KEY (lot_id) REFERENCES lots (id) ON DELETE RESTRICT;

ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_storage_bin_id FOREIGN KEY (storage_bin_id) REFERENCES storage_bins (id) ON DELETE RESTRICT;

ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_gr_line_id FOREIGN KEY (gr_line_id) REFERENCES goods_receipt_lines (id) ON DELETE RESTRICT;

ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_reverses FOREIGN KEY (reverses_movement_id) REFERENCES inventory_movements (id) ON DELETE RESTRICT;

ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_transfer_line FOREIGN KEY (transfer_line_id) REFERENCES stock_transfer_lines (id) ON DELETE RESTRICT;

ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_issue_line FOREIGN KEY (issue_line_id) REFERENCES stock_issue_lines (id) ON DELETE RESTRICT;

ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_adjustment_line FOREIGN KEY (adjustment_line_id) REFERENCES stock_adjustment_lines (id) ON DELETE RESTRICT;

ALTER TABLE inventory_movements
ADD CONSTRAINT fk_inventory_movements_production_receipt FOREIGN KEY (production_receipt_id) REFERENCES production_receipts (id) ON DELETE RESTRICT;

-- AddForeignKey stock_transfers table
ALTER TABLE stock_transfers
ADD CONSTRAINT fk_stock_transfers_by FOREIGN KEY (transferred_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE stock_transfer_lines
ADD CONSTRAINT fk_stl_transfer_id FOREIGN KEY (transfer_id) REFERENCES stock_transfers (id) ON DELETE CASCADE;

ALTER TABLE stock_transfer_lines
ADD CONSTRAINT fk_stl_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

ALTER TABLE stock_transfer_lines
ADD CONSTRAINT fk_stl_lot_id FOREIGN KEY (lot_id) REFERENCES lots (id) ON DELETE RESTRICT;

ALTER TABLE stock_transfer_lines
ADD CONSTRAINT fk_stl_from_bin FOREIGN KEY (from_bin_id) REFERENCES storage_bins (id) ON DELETE RESTRICT;

ALTER TABLE stock_transfer_lines
ADD CONSTRAINT fk_stl_to_bin FOREIGN KEY (to_bin_id) REFERENCES storage_bins (id) ON DELETE RESTRICT;

-- AddForeignKey stock_issues table
ALTER TABLE stock_issues
ADD CONSTRAINT fk_stock_issues_by FOREIGN KEY (issued_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE stock_issues
ADD CONSTRAINT fk_stock_issues_mo FOREIGN KEY (mo_id) REFERENCES manufacturing_orders (id) ON DELETE RESTRICT;

ALTER TABLE stock_issues
ADD CONSTRAINT fk_stock_issues_vendor FOREIGN KEY (vendor_id) REFERENCES vendors (id) ON DELETE RESTRICT;

ALTER TABLE stock_issue_lines
ADD CONSTRAINT fk_sil_issue_id FOREIGN KEY (issue_id) REFERENCES stock_issues (id) ON DELETE CASCADE;

ALTER TABLE stock_issue_lines
ADD CONSTRAINT fk_sil_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

ALTER TABLE stock_issue_lines
ADD CONSTRAINT fk_sil_lot_id FOREIGN KEY (lot_id) REFERENCES lots (id) ON DELETE RESTRICT;

ALTER TABLE stock_issue_lines
ADD CONSTRAINT fk_sil_bin FOREIGN KEY (storage_bin_id) REFERENCES storage_bins (id) ON DELETE RESTRICT;

-- AddForeignKey stock_adjustments table
ALTER TABLE stock_adjustments
ADD CONSTRAINT fk_stock_adjustments_by FOREIGN KEY (counted_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE stock_adjustment_lines
ADD CONSTRAINT fk_sal_adjustment_id FOREIGN KEY (adjustment_id) REFERENCES stock_adjustments (id) ON DELETE CASCADE;

ALTER TABLE stock_adjustment_lines
ADD CONSTRAINT fk_sal_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

ALTER TABLE stock_adjustment_lines
ADD CONSTRAINT fk_sal_lot_id FOREIGN KEY (lot_id) REFERENCES lots (id) ON DELETE RESTRICT;

ALTER TABLE stock_adjustment_lines
ADD CONSTRAINT fk_sal_bin FOREIGN KEY (storage_bin_id) REFERENCES storage_bins (id) ON DELETE RESTRICT;

-- AddForeignKey manufacturing_orders table
ALTER TABLE manufacturing_orders
ADD CONSTRAINT fk_mo_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

ALTER TABLE manufacturing_orders
ADD CONSTRAINT fk_mo_bom_id FOREIGN KEY (bom_id) REFERENCES boms (id) ON DELETE RESTRICT;

ALTER TABLE manufacturing_orders
ADD CONSTRAINT fk_mo_output_lot FOREIGN KEY (output_lot_id) REFERENCES lots (id) ON DELETE RESTRICT;

ALTER TABLE manufacturing_orders
ADD CONSTRAINT fk_mo_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE mo_material_lines
ADD CONSTRAINT fk_mml_mo_id FOREIGN KEY (mo_id) REFERENCES manufacturing_orders (id) ON DELETE CASCADE;

ALTER TABLE mo_material_lines
ADD CONSTRAINT fk_mml_component FOREIGN KEY (component_item_id) REFERENCES items (id) ON DELETE RESTRICT;

-- AddForeignKey production_receipts table
ALTER TABLE production_receipts
ADD CONSTRAINT fk_pr_mo_id FOREIGN KEY (mo_id) REFERENCES manufacturing_orders (id) ON DELETE RESTRICT;

ALTER TABLE production_receipts
ADD CONSTRAINT fk_pr_item_id FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE RESTRICT;

ALTER TABLE production_receipts
ADD CONSTRAINT fk_pr_lot_id FOREIGN KEY (lot_id) REFERENCES lots (id) ON DELETE RESTRICT;

ALTER TABLE production_receipts
ADD CONSTRAINT fk_pr_bin FOREIGN KEY (storage_bin_id) REFERENCES storage_bins (id) ON DELETE RESTRICT;

ALTER TABLE production_receipts
ADD CONSTRAINT fk_pr_received_by FOREIGN KEY (received_by) REFERENCES users (id) ON DELETE RESTRICT;

-- ==========================================================
-- View: phiên đăng nhập đang hoạt động (phục vụ "quản lý phiên của tôi")
-- KHÔNG lộ token_hash / user_agent. App PHẢI tự lọc WHERE user_id = <current user>.
-- ==========================================================
CREATE OR REPLACE VIEW
    active_user_sessions AS
SELECT
    id,
    user_id,
    device_id,
    device_name,
    device_type,
    platform,
    app_version,
    ip_address,
    COALESCE(last_seen_at, created_at) AS last_seen_at,
    created_at,
    expires_at
FROM
    user_sessions
WHERE
    revoked_at IS NULL
    AND expires_at > NOW();

-- ==========================================================
-- View: công thức ĐANG DÙNG HÔM NAY. Xem ghi chú ở fn_bom_in_force —
-- đây là thứ thay cho "WHERE status = 'ACTIVE'".
-- ==========================================================
CREATE OR REPLACE VIEW
    v_bom_in_force AS
SELECT
    b.*
FROM
    boms b
WHERE
    b.status = 'ACTIVE'
    AND daterange (b.effective_from, b.effective_to, '[)') @> CURRENT_DATE;

-- ==========================================================
-- View: ĐỐI SOÁT chu trình BOM (lưới an toàn cho job định kỳ) — KẾT QUẢ RỖNG = SẠCH.
-- Cần vì trg_bom_lines_no_cycle KHÔNG chạy khi pg_restore nạp dữ liệu, hoặc khi ai
-- đó ALTER TABLE ... DISABLE TRIGGER để nhập hàng loạt rồi quên bật lại.
-- ==========================================================
CREATE OR REPLACE VIEW
    v_bom_cycle_audit AS
WITH RECURSIVE
    walk AS (
        SELECT
            b.item_id AS root_item_id,
            bl.component_item_id AS item_id,
            ARRAY[b.item_id, bl.component_item_id] AS trail
        FROM
            boms b
            JOIN bom_lines bl ON bl.bom_id = b.id
        WHERE
            b.status <> 'OBSOLETE'
        UNION ALL
        SELECT
            w.root_item_id,
            bl.component_item_id,
            w.trail || bl.component_item_id
        FROM
            walk w
            JOIN boms b ON b.item_id = w.item_id
            AND b.status <> 'OBSOLETE'
            JOIN bom_lines bl ON bl.bom_id = b.id
    ) CYCLE item_id
SET
    is_cycle USING path
SELECT DISTINCT
    w.root_item_id,
    i.code AS root_code,
    i.name AS root_name,
    w.trail AS cycle_path,
    (
        SELECT
            string_agg(
                x.code,
                ' -> '
                ORDER BY
                    p.ord
            )
        FROM
            unnest(w.trail)
        WITH
            ORDINALITY AS p (item_id, ord)
            JOIN items x ON x.id = p.item_id
    ) AS cycle_path_codes
FROM
    walk w
    JOIN items i ON i.id = w.root_item_id
WHERE
    w.is_cycle;

-- ==========================================================
-- View: TỒN KHO VẬT LÝ theo (item, lô, bin) — cộng dồn từ sổ kho.
-- HAVING <> 0: bỏ các tổ hợp đã xuất hết (gồm cả cặp bút toán gốc + đảo khi huỷ phiếu).
-- ==========================================================
CREATE OR REPLACE VIEW
    v_inventory_on_hand AS
SELECT
    item_id,
    lot_id,
    storage_bin_id,
    SUM(qty_base) AS qty_on_hand,
    MAX(movement_at) AS last_movement_at
FROM
    inventory_movements
GROUP BY
    item_id,
    lot_id,
    storage_bin_id
HAVING
    SUM(qty_base) <> 0;

-- ==========================================================
-- View: TỒN SẢN XUẤT LĨNH ĐƯỢC. Đây là chỗ luồng "tạm trữ -> QC -> bảo quản" trở thành
-- ràng buộc DỮ LIỆU chứ không còn là quy ước: hàng chỉ khả dụng khi lô đã RELEASED
-- (QC đạt) VÀ đang nằm ở bin bảo quản. Mọi chỗ cấp phát nguyên liệu PHẢI dùng view này,
-- KHÔNG dùng v_inventory_on_hand — dùng nhầm là lĩnh phải hàng chưa kiểm.
-- ==========================================================
CREATE OR REPLACE VIEW
    v_inventory_available AS
SELECT
    oh.item_id,
    oh.lot_id,
    oh.storage_bin_id,
    oh.qty_on_hand,
    l.expiry_date -- phục vụ FEFO: cấp phát lô hết hạn trước
FROM
    v_inventory_on_hand oh
    JOIN lots l ON l.id = oh.lot_id
    AND l.status = 'RELEASED'
    JOIN storage_bins b ON b.id = oh.storage_bin_id
    AND b.bin_type = 'PRESERVATION'
WHERE
    oh.qty_on_hand > 0;

-- ==========================================================
-- View: TRUY VẾT LÔ HAI CHIỀU — mục đích tồn tại của cả thiết kế sổ kho.
--   Xuôi : lô thành phẩm X được làm từ những lô nguyên liệu nào? (điều tra khiếu nại)
--   Ngược: lô nguyên liệu Y đã đi vào những lô thành phẩm nào? (THU HỒI lô)
-- Nối qua lệnh sản xuất: xuất NVL (stock_issues.mo_id) <-> nhập TP (production_receipts.mo_id).
-- ==========================================================
CREATE OR REPLACE VIEW
    v_lot_genealogy AS
SELECT
    pr.lot_id AS output_lot_id,
    fp.code AS output_item_code,
    ol.lot_code AS output_lot_code,
    mo.id AS mo_id,
    mo.mo_number,
    sil.lot_id AS input_lot_id,
    cp.code AS input_item_code,
    il.lot_code AS input_lot_code,
    SUM(sil.qty_base) AS input_qty_base
FROM
    production_receipts pr
    JOIN manufacturing_orders mo ON mo.id = pr.mo_id
    JOIN items fp ON fp.id = pr.item_id
    LEFT JOIN lots ol ON ol.id = pr.lot_id
    JOIN stock_issues si ON si.mo_id = mo.id
    AND si.status = 'POSTED'
    AND si.deleted_at IS NULL
    JOIN stock_issue_lines sil ON sil.issue_id = si.id
    JOIN items cp ON cp.id = sil.item_id
    LEFT JOIN lots il ON il.id = sil.lot_id
WHERE
    pr.status = 'POSTED'
    AND pr.deleted_at IS NULL
GROUP BY
    pr.lot_id,
    fp.code,
    ol.lot_code,
    mo.id,
    mo.mo_number,
    sil.lot_id,
    cp.code,
    il.lot_code;

-- ==========================================================
-- View: còn phải xuất bao nhiêu cho mỗi lệnh sản xuất.
-- ==========================================================
CREATE OR REPLACE VIEW
    v_mo_material_status AS
SELECT
    mo.id AS mo_id,
    mo.mo_number,
    mo.status,
    i.code AS component_code,
    m.required_qty_base,
    m.issued_qty_base,
    m.required_qty_base - m.issued_qty_base AS remaining_qty_base
FROM
    mo_material_lines m
    JOIN manufacturing_orders mo ON mo.id = m.mo_id
    JOIN items i ON i.id = m.component_item_id
WHERE
    mo.deleted_at IS NULL;

-- ==========================================================
-- Trigger
-- ==========================================================
--- trigger set_updated_at
CREATE
OR REPLACE FUNCTION set_updated_at () RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW IS DISTINCT FROM OLD THEN
        NEW.updated_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;

--- tạo trigger tự động cập nhật updated_at cho tất cả table nào có field updated_at
DO $$
    DECLARE
        r        RECORD;
        trg_name TEXT;
    BEGIN
        FOR r IN
            -- LỌC BASE TABLE: information_schema.columns liệt kê cả cột của VIEW,
            -- mà view phơi updated_at (vd v_bom_in_force SELECT b.*) sẽ làm
            -- CREATE TRIGGER báo '... is a view'. Khối audit bên dưới lọc y hệt.
            SELECT c.table_schema, c.table_name
            FROM information_schema.columns c
                     JOIN information_schema.tables t
                          ON t.table_schema = c.table_schema
                              AND t.table_name = c.table_name
            WHERE c.column_name = 'updated_at'
              AND c.table_schema = 'public'
              AND t.table_type = 'BASE TABLE'
            LOOP
                trg_name := format('trg_updated_at_%s', r.table_name);

                EXECUTE format(
                        'DROP TRIGGER IF EXISTS %I ON %I.%I;',
                        trg_name,
                        r.table_schema,
                        r.table_name
                        );

                EXECUTE format(
                        'CREATE TRIGGER %I
                         BEFORE UPDATE ON %I.%I
                         FOR EACH ROW
                         EXECUTE FUNCTION set_updated_at();',
                        trg_name,
                        r.table_schema,
                        r.table_name
                        );
            END LOOP;
    END;
$$;

--- trigger fn_generic_audit_log
CREATE
OR REPLACE FUNCTION fn_generic_audit_log () RETURNS TRIGGER AS $$
DECLARE
    v_tx_id     TEXT;
    v_user_id   TEXT;
    v_record_id TEXT;

    -- Biến lưu dữ liệu Diff
    v_old_data  JSONB := NULL;
    v_new_data  JSONB := NULL;

    v_pk_values TEXT[] := '{}';
    v_row_data  JSONB;

    -- cột nhạy cảm cần che trong audit (mask theo TÊN cột, áp dụng cho mọi bảng)
    v_sensitive TEXT[] := ARRAY['password_hash', 'token_hash', 'password', 'secret', 'refresh_token'];
    v_key       TEXT;
BEGIN

    -- 1. Transaction ID (batch id)
    v_tx_id := current_setting('ich_app.current_transaction_id', true);
    IF v_tx_id = '' OR v_tx_id IS NULL THEN
        v_tx_id := uuidv7()::TEXT;
        PERFORM set_config('ich_app.current_transaction_id', v_tx_id, true);
    END IF;

    -- 2. User ID (từ app context)
    v_user_id := current_setting('ich_app.current_user_id', true);
    IF v_user_id = '' OR v_user_id IS NULL THEN
        v_user_id := 'SYSTEM';
        PERFORM set_config('ich_app.current_user_id', v_user_id, true);
    END IF;

    -- 2. XỬ LÝ DIFF JSONB THEO HÀNH ĐỘNG
    IF TG_OP = 'UPDATE' THEN
        -- Thực hiện phép so sánh (Diff)
        SELECT
            jsonb_object_agg(key, o.value),
            jsonb_object_agg(key, n.value)
        INTO v_old_data, v_new_data
        FROM jsonb_each(to_jsonb(OLD)) o
        JOIN jsonb_each(to_jsonb(NEW)) n USING (key)
        WHERE o.value IS DISTINCT FROM n.value;

        -- Nếu UPDATE nhưng dữ liệu thực tế không thay đổi (bỏ qua để không lưu rác)
        IF v_new_data IS NULL THEN
            RETURN NULL;
        END IF;

    ELSIF TG_OP = 'INSERT' THEN
        v_new_data := to_jsonb(NEW);
    ELSIF TG_OP = 'DELETE' THEN
        v_old_data := to_jsonb(OLD);
    END IF;

    -- 2b. CHE dữ liệu nhạy cảm (mask value nhưng GIỮ key để vẫn biết trường đó có thay đổi)
    FOREACH v_key IN ARRAY v_sensitive LOOP
        IF v_old_data ? v_key THEN
            v_old_data := jsonb_set(v_old_data, ARRAY[v_key], '"***REDACTED***"');
        END IF;
        IF v_new_data ? v_key THEN
            v_new_data := jsonb_set(v_new_data, ARRAY[v_key], '"***REDACTED***"');
        END IF;
    END LOOP;

    -- 3. XÁC ĐỊNH KHÓA CHÍNH (Từ NEW hoặc OLD)
    -- Dùng NEW cho INSERT/UPDATE, dùng OLD cho DELETE
    v_row_data := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;

    IF TG_NARGS > 0 THEN
        FOR i IN 0 .. (TG_NARGS - 1) LOOP
            v_pk_values := array_append(v_pk_values, (v_row_data ->> TG_ARGV[i]));
        END LOOP;
        v_record_id := array_to_string(v_pk_values, ':');
    ELSE
        -- Fallback an toàn nếu lúc cài trigger quên truyền tham số
        v_record_id := COALESCE(v_row_data ->> 'id', 'UNKNOWN');
    END IF;

    -- 4. GHI LOG
    INSERT INTO audit_logs (transaction_id, table_name, record_id, action, old_data, new_data, changed_by)
    VALUES (
        v_tx_id,
        TG_TABLE_NAME,
        v_record_id,
        TG_OP,
        v_old_data,
        v_new_data,
        v_user_id
    );

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- thêm trigger fn_generic_audit_log cho tất cả bảng trừ bảng audit_logs
DO $$
DECLARE
    rec RECORD;
    v_pk_cols TEXT;
BEGIN
    FOR rec IN
        -- Query này sinh ra danh sách bảng kèm theo các cột PK định dạng thành chuỗi cách nhau bằng dấu phẩy
        SELECT t.table_name,
               COALESCE((
                   SELECT string_agg('''' || a.attname || '''', ', ')
                   FROM pg_index i
                   JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                   WHERE i.indrelid = t.table_name::regclass AND i.indisprimary
               ), '''id''') as pk_args
        FROM information_schema.tables t
        WHERE t.table_schema = 'public'
          AND t.table_type = 'BASE TABLE'
          AND t.table_name NOT LIKE 'audit_logs%'
          AND t.table_name <> 'user_sessions'   -- loại trừ: tránh audit phình + lọt token_hash do last_seen_at cập nhật mỗi request
          AND t.table_name <> 'document_number_counters'  -- bảng kỹ thuật: mỗi lần cấp số không cần audit
          AND t.table_name <> 'inventory_movements'       -- đã append-only + chặn UPDATE/DELETE: audit chỉ chép lại y nguyên mỗi INSERT
    LOOP
        -- Khai báo Trigger Insert/Delete
        EXECUTE format('
            DROP TRIGGER IF EXISTS trg_audit_ins_del_%I ON %I;
            CREATE TRIGGER trg_audit_ins_del_%I
            AFTER INSERT OR DELETE ON %I
            FOR EACH ROW EXECUTE FUNCTION fn_generic_audit_log(%s);',
            rec.table_name, rec.table_name, rec.table_name, rec.table_name, rec.pk_args);

        -- Khai báo Trigger Update (Có thêm mệnh đề IS DISTINCT FROM)
        EXECUTE format('
            DROP TRIGGER IF EXISTS trg_audit_upd_%I ON %I;
            CREATE TRIGGER trg_audit_upd_%I
            AFTER UPDATE ON %I
            FOR EACH ROW
            WHEN (OLD.* IS DISTINCT FROM NEW.*) -- Bỏ qua nếu data không đổi
            EXECUTE FUNCTION fn_generic_audit_log(%s);',
            rec.table_name, rec.table_name, rec.table_name, rec.table_name, rec.pk_args);
    END LOOP;
END $$;

-- ==========================================================
-- Danh mục file
-- ==========================================================
-- CREATE TABLE IF NOT EXISTS files
-- (
--     id            UUID           NOT NULL DEFAULT uuidv7(),
--     original_name TEXT           NOT NULL, -- tên file người dùng upload
--     mime_type     VARCHAR(100)   NOT NULL, -- loại file
--     destination   TEXT           NOT NULL, -- đường dẫn ngắn đến file
--     file_name     TEXT           NOT NULL, -- tên file
--     path          TEXT           NOT NULL, -- đường dẫn đầy đủ đến file
--     size          BIGINT         NOT NULL, -- kích thước file
--     uploaded_by   UUID           NOT NULL, -- upload bởi ai
--     deleted_at    TIMESTAMPTZ(3),          -- xoá lúc nào
--     created_at    TIMESTAMPTZ(3) NOT NULL DEFAULT NOW(),
--     updated_at    TIMESTAMPTZ(3) NOT NULL DEFAULT NOW(),
--     CONSTRAINT pk_files PRIMARY KEY (id)
-- );
-- CREATE INDEX idx_files_deleted_at ON files (deleted_at)
--     WHERE deleted_at IS NULL;
-- CREATE UNIQUE INDEX uix_files_path ON files (path)
--     WHERE deleted_at IS NULL;
-- CREATE INDEX IF NOT EXISTS idx_files_uploaded_by ON files (uploaded_by);
-- CREATE TABLE IF NOT EXISTS user_avatars
-- (
--     file_id    UUID           NOT NULL,
--     user_id    UUID           NOT NULL,
--     width      INTEGER        NOT NULL,
--     height     INTEGER        NOT NULL,
--     is_primary BOOLEAN        NOT NULL DEFAULT FALSE, -- Hình đại diện
--     deleted_at TIMESTAMPTZ(3),                        -- xoá lúc nào
--     created_at TIMESTAMPTZ(3) NOT NULL DEFAULT NOW(),
--     CONSTRAINT pk_user_avatars PRIMARY KEY (file_id, user_id)
-- );
-- CREATE UNIQUE INDEX IF NOT EXISTS uq_user_avatars_one_primary
--     ON user_avatars (user_id) WHERE is_primary IS TRUE AND deleted_at IS NULL;
-- --- AddForeignKey user_avatars table
-- ALTER TABLE user_avatars
--     ADD CONSTRAINT fk_user_avatars_user_id FOREIGN KEY (user_id)
--         REFERENCES users (id) ON DELETE RESTRICT ON UPDATE CASCADE;
-- ALTER TABLE user_avatars
--     ADD CONSTRAINT fk_user_avatars_file_id FOREIGN KEY (file_id)
--         REFERENCES files (id) ON DELETE CASCADE ON UPDATE CASCADE;
--- AddForeignKey files table
-- ALTER TABLE files
--     ADD CONSTRAINT fk_files_uploaded_by FOREIGN KEY (uploaded_by)
--         REFERENCES users (id) ON DELETE RESTRICT ON UPDATE CASCADE;
-- ==========================================================
-- Extension
-- ==========================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ==========================================================
-- Config
-- ==========================================================
-- Không gắn cứng tên database: dùng current_database() để chạy được trên mọi môi trường.
-- Lưu ý: ALTER DATABASE ... SET chỉ có hiệu lực với các kết nối MỚI.
DO $$
    BEGIN
        EXECUTE format('ALTER DATABASE %I SET datestyle = %L', current_database(), 'ISO, DMY');
        EXECUTE format('ALTER DATABASE %I SET timezone = %L', current_database(), 'Asia/Ho_Chi_Minh');
    END
$$;

-- create user_sessions table
CREATE TABLE IF NOT EXISTS
    user_sessions (
        id UUID NOT NULL DEFAULT uuidv7 (),
        user_id UUID NOT NULL,
        refresh_token_hash CHAR(64) NOT NULL,
        previous_token_hash CHAR(64),
        rotated_at TIMESTAMPTZ (3),
        device_name VARCHAR(255), -- Human-readable: "Chrome 124 · Windows 11", "MyApp 2.1 · macOS 14"
        device_type VARCHAR(20) NOT NULL, -- 'web' | 'desktop' | 'mobile'
        app_version VARCHAR(50), -- desktop: version app; web: version bản build frontend
        user_agent TEXT, -- Raw User-Agent header, dùng để debug
        ip_address INET, -- IP lúc login, dùng để hiển thị "đăng nhập từ đâu"
        revoked_at TIMESTAMPTZ (3),
        revoke_reason VARCHAR(20),
        -- 'LOGOUT'  : user tự logout
        -- 'FORCED'  : user logout tất cả thiết bị / tài khoản bị khoá
        -- 'USER'    : user thu hồi
        -- 'EXPIRED' : cleanup job đánh dấu sau khi hết hạn
        -- 'REUSED'  : refresh token cũ bị dùng lại (nghi bị đánh cắp)
        last_seen_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(), -- lần cuối truy cập 
        expires_at TIMESTAMPTZ (3) NOT NULL, -- hạn trượt (gia hạn mỗi lần refresh)
        absolute_expires_at TIMESTAMPTZ (3) NOT NULL, -- hạn cuối cùng
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT chk_revoke_reason CHECK (
            revoke_reason IN ('LOGOUT', 'FORCED', 'USER', 'EXPIRED', 'REUSED')
        ),
        CONSTRAINT chk_user_sessions_device_type CHECK (device_type IN ('web', 'desktop', 'mobile')),
        CONSTRAINT pk_user_sessions PRIMARY KEY (id)
    );

-- ==========================================================
-- Danh mục file
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    files (
        id UUID NOT NULL DEFAULT uuidv7 (),
        original_name TEXT NOT NULL, -- tên file người dùng upload
        mime_type VARCHAR(100) NOT NULL, -- loại file
        destination TEXT NOT NULL, -- đường dẫn ngắn đến file
        file_name TEXT NOT NULL, -- tên file
        path TEXT NOT NULL, -- đường dẫn đầy đủ đến file
        size BIGINT NOT NULL, -- kích thước file
        uploaded_by UUID NOT NULL, -- upload bởi ai
        deleted_at TIMESTAMPTZ (3), -- xoá lúc nào
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_files PRIMARY KEY (id)
    );

-- ==========================================================
-- audit_logs table
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

-- ==========================================================
-- Danh mục quyền và vai trò
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    permissions (
        id UUID NOT NULL DEFAULT uuidv7 (),
        code VARCHAR(100) NOT NULL, -- vd: CHEMICAL_CREATE, PO_VIEW
        description TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_permissions PRIMARY KEY (id),
        CONSTRAINT permissions_code_unique UNIQUE (code)
    );

CREATE TABLE IF NOT EXISTS
    role_permissions (
        role_id UUID NOT NULL,
        permission_id UUID NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_role_permissions PRIMARY KEY (role_id, permission_id)
    );

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

-- ==========================================================
-- Danh mục người dùng
-- ==========================================================
CREATE TABLE IF NOT EXISTS
    user_roles (
        user_id UUID NOT NULL,
        role_id UUID NOT NULL,
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_id)
    );

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

CREATE TABLE IF NOT EXISTS
    user_avatars (
        file_id UUID NOT NULL,
        user_id UUID NOT NULL,
        width INTEGER NOT NULL,
        height INTEGER NOT NULL,
        is_primary BOOLEAN NOT NULL DEFAULT FALSE, -- Hình đại diện
        deleted_at TIMESTAMPTZ (3), -- xoá lúc nào
        created_at TIMESTAMPTZ (3) NOT NULL DEFAULT NOW(),
        CONSTRAINT pk_user_avatars PRIMARY KEY (file_id, user_id)
    );

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

-- ==========================================================
-- Index
-- ==========================================================
-- create user_sessions index
CREATE INDEX idx_user_revoked ON user_sessions (user_id, revoked_at);

-- liệt kê nhanh phiên đang hoạt động + hỗ trợ "đăng xuất mọi thiết bị khác"
CREATE INDEX idx_user_sessions_active ON user_sessions (user_id, expires_at)
WHERE
    revoked_at IS NULL;

-- create file index
CREATE INDEX idx_files_deleted_at ON files (deleted_at)
WHERE
    deleted_at IS NULL;

CREATE UNIQUE INDEX uix_files_path ON files (path)
WHERE
    deleted_at IS NULL;

--create audit_logs index
CREATE INDEX IF NOT EXISTS idx_audit_logs_table_record ON audit_logs (table_name, record_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tx ON audit_logs (transaction_id);

-- create roles index
CREATE INDEX IF NOT EXISTS idx_roles_status ON roles (status)
WHERE
    deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_roles_name ON roles (name)
WHERE
    deleted_at IS NULL;

-- create users index
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users (lower(email))
WHERE
    deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_users_status ON users (status)
WHERE
    deleted_at IS NULL;

-- create user_avatars index
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_avatars_one_primary ON user_avatars (user_id)
WHERE
    is_primary IS TRUE
    AND deleted_at IS NULL;

-- create password_tokens index
CREATE INDEX idx_password_tokens_user_id ON password_tokens (user_id);

CREATE INDEX idx_password_tokens_expires_at ON password_tokens (expires_at);

-- index chiều ngược cho bảng nối (FK enforcement + "ai có permission/role X")
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions (permission_id);

CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles (role_id);

-- index cho FK files.uploaded_by
CREATE INDEX IF NOT EXISTS idx_files_uploaded_by ON files (uploaded_by);

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

--- AddForeignKey user_avatars table
ALTER TABLE user_avatars
ADD CONSTRAINT fk_user_avatars_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE user_avatars
ADD CONSTRAINT fk_user_avatars_file_id FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE ON UPDATE CASCADE;

--- AddForeignKey files table
ALTER TABLE files
ADD CONSTRAINT fk_files_uploaded_by FOREIGN KEY (uploaded_by) REFERENCES users (id) ON DELETE RESTRICT ON UPDATE CASCADE;

-- ==========================================================
-- View: phiên đăng nhập đang hoạt động (phục vụ "quản lý phiên của tôi")
-- KHÔNG lộ token_hash / user_agent. App PHẢI tự lọc WHERE user_id = <current user>.
-- ==========================================================
CREATE OR REPLACE VIEW
    active_user_sessions AS
SELECT
    id,
    user_id,
    rotated_at,
    device_name,
    device_type,
    app_version,
    ip_address,
    expires_at,
    absolute_expires_at,
    created_at,
    updated_at
FROM
    user_sessions
WHERE
    revoked_at IS NULL
    AND expires_at > NOW();

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
            SELECT c.table_schema, c.table_name
            FROM information_schema.columns c
                     JOIN information_schema.tables t
                          ON c.table_schema = t.table_schema
                              AND c.table_name = t.table_name
                              AND t.table_type = 'BASE TABLE'
            WHERE c.column_name = 'updated_at'
              AND c.table_schema = 'public'
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
          AND t.table_name <> '_sqlx_migrations' -- loại trừ: bảng theo dõi migration của sqlx
          AND t.table_name <> 'user_sessions'   -- loại trừ: tránh audit phình + lọt token_hash do last_seen_at cập nhật mỗi request
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

-- Tạo các partition theo tháng (Nên dùng cronjob hoặc pg_partman để tạo tự động)
-- CREATE TABLE audit_logs_2026_04 PARTITION OF audit_logs FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
-- CREATE TABLE audit_logs_2026_05 PARTITION OF audit_logs FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
-- 1. Tạo schema cho pg_partman (khuyên dùng)
CREATE SCHEMA IF NOT EXISTS partman;

-- 2. Kích hoạt extension (Cần quyền Superuser hoặc Owner)
CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;

-- Khởi tạo partman cho audit_logs.
-- Bọc idempotent: an toàn khi chạy lại, hoặc khi cài partman SAU (xem DEPLOY.md).
DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM partman.part_config
                       WHERE parent_table = 'public.audit_logs') THEN
            PERFORM partman.create_parent(
                    p_parent_table := 'public.audit_logs', -- Tên bảng cha (Schema.Table)
                    p_control := 'changed_at', -- Cột dùng để phân vùng
                    p_interval := '1 month', -- Kích thước mỗi phân vùng (mỗi partition = 1 tháng)
                    p_premake := 3 -- Số lượng partition tương lai cần tạo sẵn
                    );
        END IF;
    END
$$;

-- ==========================================================
-- Retention: giữ 1 năm, hết hạn DROP hẳn partition (thu hồi disk).
-- pg_partman_bgw (bật trong docker-compose) tự thực thi khi chạy maintenance — không cần cron riêng.
-- ==========================================================
UPDATE partman.part_config
SET
    retention = '1 year',
    retention_keep_table = false -- false = DROP partition cũ; true = chỉ detach (vẫn giữ disk)
WHERE
    parent_table = 'public.audit_logs';
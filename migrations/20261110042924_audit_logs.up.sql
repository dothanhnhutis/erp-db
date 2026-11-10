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

--create audit_logs index
CREATE INDEX IF NOT EXISTS idx_audit_logs_table_record ON audit_logs (table_name, record_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tx ON audit_logs (transaction_id);

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
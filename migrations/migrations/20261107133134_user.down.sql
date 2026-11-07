-- 1. Gỡ cấu hình pg_partman cho audit_logs
DO $$
    BEGIN
        IF to_regclass('partman.part_config') IS NOT NULL THEN
            DELETE FROM partman.part_config WHERE parent_table = 'public.audit_logs';
        END IF;
    END
$$;

-- bảng template do partman.create_parent tạo ra (không thuộc extension nên phải xoá tay)
DROP TABLE IF EXISTS partman.template_public_audit_logs;

-- 2. View (phụ thuộc user_sessions nên xoá trước)
DROP VIEW IF EXISTS active_user_sessions;

-- 3. Hàm audit + MỌI trigger đang dùng nó.
-- CASCADE quan trọng: nếu bản up cũ đã gắn trigger audit lên _sqlx_migrations,
-- sqlx sẽ lỗi khi xoá dòng của migration này sau khi chạy file down.
DROP FUNCTION IF EXISTS fn_generic_audit_log () CASCADE;

-- 4. Bảng. Xoá chung một lệnh nên Postgres tự xử lý khoá ngoại giữa các bảng này;
-- các partition của audit_logs bị xoá theo bảng cha. Trigger trên bảng cũng bị xoá theo.
DROP TABLE IF EXISTS user_avatars,
password_tokens,
user_sessions,
user_roles,
role_permissions,
files,
users,
roles,
permissions,
audit_logs;

-- 5. Hàm cập nhật updated_at
DROP FUNCTION IF EXISTS set_updated_at ();

-- 6. Extension và schema.
-- Bỏ các dòng này nếu migration khác (hoặc database có sẵn từ trước) cũng dùng chúng.
DROP EXTENSION IF EXISTS pg_partman;

DROP SCHEMA IF EXISTS partman;

DROP EXTENSION IF EXISTS pgcrypto;

-- 7. Trả cấu hình database về mặc định
DO $$
    BEGIN
        EXECUTE format('ALTER DATABASE %I RESET datestyle', current_database());
        EXECUTE format('ALTER DATABASE %I RESET timezone', current_database());
    END
$$;
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

-- 3. Hàm audit + MỌI trigger đang dùng nó.
-- CASCADE quan trọng: nếu bản up cũ đã gắn trigger audit lên _sqlx_migrations,
-- sqlx sẽ lỗi khi xoá dòng của migration này sau khi chạy file down.
DROP FUNCTION IF EXISTS fn_generic_audit_log () CASCADE;

-- 4. Bảng. Xoá chung một lệnh nên Postgres tự xử lý khoá ngoại giữa các bảng này;
-- các partition của audit_logs bị xoá theo bảng cha. Trigger trên bảng cũng bị xoá theo.
DROP TABLE IF EXISTS audit_logs;

-- 6. Extension và schema.
-- Bỏ các dòng này nếu migration khác (hoặc database có sẵn từ trước) cũng dùng chúng.
DROP EXTENSION IF EXISTS pg_partman;

DROP SCHEMA IF EXISTS partman;
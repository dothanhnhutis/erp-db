-- 2. View (phụ thuộc user_sessions nên xoá trước)
DROP VIEW IF EXISTS active_user_sessions;

-- 4. Bảng. Xoá chung một lệnh nên Postgres tự xử lý khoá ngoại giữa các bảng này;
DROP TABLE IF EXISTS user_avatars,
password_tokens,
user_sessions,
user_roles,
role_permissions,
files,
users,
roles,
permissions;

-- 5. Hàm cập nhật updated_at
DROP FUNCTION IF EXISTS set_updated_at ();

-- 6. Extension và schema.
-- Bỏ các dòng này nếu migration khác (hoặc database có sẵn từ trước) cũng dùng chúng.
DROP EXTENSION IF EXISTS pgcrypto;

-- 7. Trả cấu hình database về mặc định
DO $$
    BEGIN
        EXECUTE format('ALTER DATABASE %I RESET datestyle', current_database());
        EXECUTE format('ALTER DATABASE %I RESET timezone', current_database());
    END
$$;
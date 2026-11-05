
-- =====================================================
-- AUTO SHOP PRO
-- FILE: database/activate_shop_license.sql
-- PURPOSE: Activate shop license after owner setup
-- =====================================================

BEGIN;

-- =====================================================
-- 1. CREATE LICENSE ACTIVATION FUNCTION
-- =====================================================

CREATE OR REPLACE FUNCTION public.activate_shop_license(
    p_shop_id uuid,
    p_license_id uuid,
    p_trial_days integer DEFAULT 14
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_status text;
    v_shop_id uuid;
    v_license_id uuid;
BEGIN

    -- ตรวจสอบจำนวนวันทดลอง
    IF p_trial_days IS NULL
       OR p_trial_days < 1
       OR p_trial_days > 365 THEN

        RAISE EXCEPTION 'Invalid trial days';
    END IF;

    -- ตรวจสอบว่าร้านและ License เป็นคู่กันจริง
    -- พร้อมล็อกแถวป้องกันการเปิดใช้งานซ้ำพร้อมกัน
    SELECT
        l.status,
        s.id,
        l.id
    INTO
        v_status,
        v_shop_id,
        v_license_id
    FROM public.shops AS s
    INNER JOIN public.licenses AS l
        ON l.id = s.license_id
    WHERE s.id = p_shop_id
      AND l.id = p_license_id
    FOR UPDATE OF s, l;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Shop/license pair not found';
    END IF;

    -- อนุญาตเฉพาะ License ที่ยังไม่เปิดใช้งาน
    IF v_status <> 'suspended' THEN
        RAISE EXCEPTION 'License is not pending activation';
    END IF;

    -- เปิดใช้งาน License
    UPDATE public.licenses
    SET
        status = 'active',
        plan = 'trial',
        starts_at = COALESCE(starts_at, now()),
        expires_at = COALESCE(
            expires_at,
            now() + make_interval(days => p_trial_days)
        ),
        updated_at = now()
    WHERE id = v_license_id
      AND status = 'suspended';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'License activation failed';
    END IF;

    -- เปิดใช้งานร้าน
    UPDATE public.shops
    SET
        is_active = true,
        updated_at = now()
    WHERE id = v_shop_id
      AND license_id = v_license_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Shop activation failed';
    END IF;

    RETURN true;

END;
$$;

-- =====================================================
-- 2. SECURITY: RESTRICT FUNCTION EXECUTION
-- =====================================================

REVOKE ALL ON FUNCTION
public.activate_shop_license(uuid, uuid, integer)
FROM PUBLIC;

REVOKE ALL ON FUNCTION
public.activate_shop_license(uuid, uuid, integer)
FROM anon;

REVOKE ALL ON FUNCTION
public.activate_shop_license(uuid, uuid, integer)
FROM authenticated;

GRANT EXECUTE ON FUNCTION
public.activate_shop_license(uuid, uuid, integer)
TO service_role;

COMMIT;

-- =====================================================
-- END OF FILE
-- =====================================================

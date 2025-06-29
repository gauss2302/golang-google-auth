-- Migration to drop the skills table and all related objects

-- Drop indexes first (they depend on the table)
DROP INDEX IF EXISTS idx_skills_user_category_name;
DROP INDEX IF EXISTS idx_skills_user_name_unique;
DROP INDEX IF EXISTS idx_skills_name_lower;
DROP INDEX IF EXISTS idx_skills_user_category;
DROP INDEX IF EXISTS idx_skills_user_id;

-- Drop the table (this will also drop any remaining constraints)
DROP TABLE IF EXISTS skills;
-- Migration to create the skills table with proper constraints and indexes

CREATE TABLE skills (
    -- Primary key using UUID for consistency with users table
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Foreign key reference to users table with cascade delete
    -- If a user is deleted, their skills are automatically removed
                        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Skill name - required field with reasonable length limit
    -- VARCHAR instead of TEXT for better indexing performance
                        name VARCHAR(100) NOT NULL,

    -- Skill category - required field with enum-like constraint
    -- Using CHECK constraint to enforce valid categories at database level
                        category VARCHAR(20) NOT NULL CHECK (category IN (
                                                                          'language', 'framework', 'tool', 'database', 'other'
                            )),

    -- Proficiency level - optional field with valid range constraint
    -- 0 means not set, 1-5 represents beginner to expert levels
                        proficiency INTEGER DEFAULT 0 CHECK (proficiency >= 0 AND proficiency <= 5),

    -- Audit timestamps for tracking when skills were added/modified
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Indexes for efficient querying

-- Primary index for user-based queries (most common access pattern)
-- This will be used for fetching all skills for a user's profile
CREATE INDEX idx_skills_user_id ON skills(user_id);

-- Composite index for category-based filtering within user skills
-- Enables efficient queries like "show me all programming languages for this user"
CREATE INDEX idx_skills_user_category ON skills(user_id, category);

-- Index for skill name searches (case-insensitive)
-- Useful for autocomplete and duplicate detection
CREATE INDEX idx_skills_name_lower ON skills(LOWER(name));

-- Composite index for efficient ordering and pagination
-- Supports queries ordered by category and name
CREATE INDEX idx_skills_user_category_name ON skills(user_id, category, name);

-- Unique constraint to prevent duplicate skills per user
-- A user cannot have the same skill (by name) multiple times
-- Using LOWER() to make the constraint case-insensitive
CREATE UNIQUE INDEX idx_skills_user_name_unique ON skills(user_id, LOWER(name));

-- Add a comment for documentation
COMMENT ON TABLE skills IS 'User skills with proficiency levels and categorization';
COMMENT ON COLUMN skills.proficiency IS 'Proficiency level: 0=not set, 1=beginner, 2=novice, 3=intermediate, 4=advanced, 5=expert';
COMMENT ON COLUMN skills.category IS 'Skill category: language, framework, tool, database, or other';
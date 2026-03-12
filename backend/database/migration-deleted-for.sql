-- Add deleted_for column to messages table
-- Run this SQL in Supabase SQL Editor (https://supabase.com/dashboard → SQL Editor)

ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted_for UUID[] DEFAULT '{}';

COMMENT ON COLUMN messages.deleted_for IS 'Array of user IDs who have deleted this message for themselves. Message is hidden from these users but remains for others.';

-- Verify the column was added
SELECT column_name, data_type, column_default
FROM information_schema.columns 
WHERE table_name = 'messages' AND column_name = 'deleted_for';

-- FOOTGUN 01 -- "we'll turn RLS on later"
-- The single most common audit finding: the table is exposed through the auto
-- generated REST API, and RLS was never enabled -- or got disabled during a
-- debugging session and the change shipped.
alter table public.projects disable row level security;

-- ───────────────────────────────────────────────────────────────────────
--  PATCH: Fix infinite recursion in setlists / songs / setlist_shares RLS
--
--  What was wrong:
--    The old policies cross-referenced each other:
--      • setlists policies queried setlist_shares
--      • setlist_shares policies queried setlists
--      • songs policies queried setlists AND setlist_shares
--    When Postgres evaluated any of these tables, it triggered the
--    other table's policies, which triggered THIS table's policies
--    again — infinite recursion, the planner errors out, every
--    insert/select fails with:
--        "infinite recursion detected in policy for relation 'setlists'"
--
--  How this fixes it:
--    All cross-table checks are wrapped in SECURITY DEFINER functions.
--    Inside such a function, RLS is bypassed (the function runs as its
--    owner, not the caller), so the lookup doesn't re-trigger any
--    policy. That breaks the recursion cycle.
--
--  How to apply:
--    Supabase dashboard → SQL Editor → New query → paste this whole
--    file → Run. Safe to re-run; everything is idempotent.
-- ───────────────────────────────────────────────────────────────────────

-- ── HELPER FUNCTIONS ──────────────────────────────────────────────────
-- Each one answers a single yes/no question about the current user's
-- relationship to a setlist. They're declared SECURITY DEFINER so the
-- internal SELECT runs with elevated privileges and skips RLS, which
-- is what breaks the recursion.

create or replace function public.user_owns_setlist(p_setlist_id uuid)
returns boolean
language sql security definer stable
set search_path = public
as $$
  select exists (
    select 1 from public.setlists sl
    where sl.id = p_setlist_id and sl.owner_id = auth.uid()
  );
$$;

create or replace function public.user_can_view_setlist(p_setlist_id uuid)
returns boolean
language sql security definer stable
set search_path = public
as $$
  select exists (
    select 1 from public.setlist_shares s
    where s.setlist_id = p_setlist_id and s.shared_with = auth.uid()
  );
$$;

create or replace function public.user_can_edit_setlist(p_setlist_id uuid)
returns boolean
language sql security definer stable
set search_path = public
as $$
  select exists (
    select 1 from public.setlist_shares s
    where s.setlist_id = p_setlist_id
      and s.shared_with = auth.uid()
      and s.permission   = 'edit'
  );
$$;

grant execute on function public.user_owns_setlist(uuid)     to authenticated;
grant execute on function public.user_can_view_setlist(uuid) to authenticated;
grant execute on function public.user_can_edit_setlist(uuid) to authenticated;


-- ── SETLISTS POLICIES ─────────────────────────────────────────────────
-- Owner can do anything. Shared users can SELECT, and 'edit' shared
-- users can also UPDATE. None of these now query setlist_shares
-- directly — they go through the helper functions instead.

drop policy if exists setlists_owner_all      on public.setlists;
drop policy if exists setlists_shared_select  on public.setlists;
drop policy if exists setlists_shared_update  on public.setlists;

create policy setlists_owner_all on public.setlists
  for all
  using       (auth.uid() = owner_id)
  with check  (auth.uid() = owner_id);

create policy setlists_shared_select on public.setlists
  for select
  using (public.user_can_view_setlist(id));

create policy setlists_shared_update on public.setlists
  for update
  using (public.user_can_edit_setlist(id));


-- ── SONGS POLICIES ────────────────────────────────────────────────────
-- Same model, reached via parent setlist. Cross-table checks go through
-- the helper functions so we don't recurse.

drop policy if exists songs_owner_all     on public.songs;
drop policy if exists songs_shared_select on public.songs;
drop policy if exists songs_shared_mutate on public.songs;

create policy songs_owner_all on public.songs
  for all
  using      (public.user_owns_setlist(setlist_id))
  with check (public.user_owns_setlist(setlist_id));

create policy songs_shared_select on public.songs
  for select
  using (public.user_can_view_setlist(setlist_id));

create policy songs_shared_mutate on public.songs
  for all
  using      (public.user_can_edit_setlist(setlist_id))
  with check (public.user_can_edit_setlist(setlist_id));


-- ── SETLIST_SHARES POLICIES ───────────────────────────────────────────
-- Owner of a setlist can manage its shares (read + write). Recipients
-- can see (but not modify) the shares that grant them access.

drop policy if exists shares_owner_all        on public.setlist_shares;
drop policy if exists shares_recipient_select on public.setlist_shares;

create policy shares_owner_all on public.setlist_shares
  for all
  using      (public.user_owns_setlist(setlist_id))
  with check (public.user_owns_setlist(setlist_id));

create policy shares_recipient_select on public.setlist_shares
  for select
  using (shared_with = auth.uid());


-- Done. Try the Share button again from the app — sync should succeed
-- and the setlist row should appear in the setlists table.

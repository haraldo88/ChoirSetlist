-- ───────────────────────────────────────────────────────────────────────
--  Choir Setlist — Supabase schema
--
--  How to apply:
--    1. Open https://supabase.com/dashboard
--    2. Pick your project → SQL Editor → New query
--    3. Paste this whole file → Run
--
--  Idempotent: safe to re-run. Tables won't be recreated; policies and
--  triggers are dropped + re-created so policy edits propagate cleanly.
--
--  What it creates:
--    profiles         — per-user info mirroring auth.users (email, name)
--    setlists         — one row per setlist; each setlist has an owner
--    songs            — child rows of a setlist
--    setlist_shares   — explicit access grants (view / edit) for non-owners
--
--  Sharing semantics, recap:
--    'view' → recipient sees the setlist read-only
--    'edit' → recipient can read AND edit (and edit child songs)
--    'copy' → handled in the client: we INSERT a brand-new setlist owned
--             by the recipient, no row in setlist_shares
-- ───────────────────────────────────────────────────────────────────────

create extension if not exists pgcrypto;

-- ── TABLES ─────────────────────────────────────────────────────────────

create table if not exists public.profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  email         text unique not null,
  display_name  text not null,
  created_at    timestamptz default now()
);

create table if not exists public.setlists (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid not null references auth.users(id) on delete cascade,
  name        text not null,
  position    int  default 0,
  created_at  timestamptz default now(),
  updated_at  timestamptz default now()
);

create table if not exists public.songs (
  id          uuid primary key default gen_random_uuid(),
  setlist_id  uuid not null references public.setlists(id) on delete cascade,
  name        text not null default '',
  time_sig    text not null default '4/4',
  tempo       int  not null default 120,
  notes       jsonb not null default '[]'::jsonb,
  position    int  default 0,
  created_at  timestamptz default now(),
  updated_at  timestamptz default now()
);

create table if not exists public.setlist_shares (
  id           uuid primary key default gen_random_uuid(),
  setlist_id   uuid not null references public.setlists(id) on delete cascade,
  shared_with  uuid not null references auth.users(id) on delete cascade,
  permission   text not null check (permission in ('view', 'edit')),
  created_at   timestamptz default now(),
  unique (setlist_id, shared_with)
);

-- Queue for shares targeting people who don't have an account yet.
-- When they sign up, the handle_new_user trigger promotes any matching
-- row in this table into a real setlist_shares row.

create table if not exists public.pending_invites (
  id              uuid primary key default gen_random_uuid(),
  setlist_id      uuid not null references public.setlists(id) on delete cascade,
  inviter_id      uuid not null references auth.users(id)      on delete cascade,
  recipient_email text not null,
  permission      text not null check (permission in ('view','edit')),
  created_at      timestamptz default now(),
  unique (setlist_id, recipient_email)
);

create index if not exists setlists_owner_position_idx     on public.setlists(owner_id, position);
create index if not exists songs_setlist_position_idx      on public.songs(setlist_id, position);
create index if not exists setlist_shares_shared_with_idx  on public.setlist_shares(shared_with);
create index if not exists pending_invites_email_idx       on public.pending_invites(lower(recipient_email));

-- ── updated_at TRIGGERS ────────────────────────────────────────────────

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists setlists_updated_at on public.setlists;
create trigger setlists_updated_at
  before update on public.setlists
  for each row execute function public.set_updated_at();

drop trigger if exists songs_updated_at on public.songs;
create trigger songs_updated_at
  before update on public.songs
  for each row execute function public.set_updated_at();

-- ── AUTO-CREATE PROFILE ON SIGNUP + PROMOTE PENDING INVITES ────────────
-- When a user signs up via Supabase Auth we do two things:
--   1. Mirror them into public.profiles (so the app can look them up).
--   2. Promote any rows in pending_invites for their email into real
--      setlist_shares — that way an invite sent before they had an
--      account "just works" when they finally sign up.

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer
set search_path = public
as $$
declare
  v_email text;
begin
  v_email := lower(new.email);

  insert into public.profiles (id, email, display_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1))
  );

  insert into public.setlist_shares (setlist_id, shared_with, permission)
  select pi.setlist_id, new.id, pi.permission
    from public.pending_invites pi
   where lower(pi.recipient_email) = v_email
  on conflict (setlist_id, shared_with) do update set permission = excluded.permission;

  delete from public.pending_invites
   where lower(recipient_email) = v_email;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── ROW-LEVEL SECURITY ─────────────────────────────────────────────────
-- Every table gets RLS turned on. Without explicit policies, the table
-- becomes inaccessible — which is what we want by default.

alter table public.profiles        enable row level security;
alter table public.setlists        enable row level security;
alter table public.songs           enable row level security;
alter table public.setlist_shares  enable row level security;
alter table public.pending_invites enable row level security;

-- ── SECURITY-DEFINER ACCESS HELPERS ────────────────────────────────────
-- These tiny yes/no functions answer "does the current user own / view /
-- edit this setlist?" without re-triggering RLS. They're essential — if
-- the cross-table policies below were written as plain EXISTS subqueries
-- against setlists / setlist_shares, evaluating either table would
-- trigger the other table's policy and Postgres would error out with
-- "infinite recursion detected in policy for relation 'setlists'".
--
-- SECURITY DEFINER means the function runs as its owner (schema owner),
-- which bypasses RLS for the SELECT inside the function body — exactly
-- what we need to break the recursion cycle.

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

-- profiles: each user manages their own row. Other users cannot read it
-- directly — share lookups go through the security-definer RPC below
-- so we don't expose the email column to enumeration.

drop policy if exists profiles_select_own on public.profiles;
drop policy if exists profiles_update_own on public.profiles;
drop policy if exists profiles_insert_own on public.profiles;

create policy profiles_select_own on public.profiles
  for select using (auth.uid() = id);
create policy profiles_update_own on public.profiles
  for update using (auth.uid() = id);
create policy profiles_insert_own on public.profiles
  for insert with check (auth.uid() = id);

-- setlists: owner has full access (CRUD). Shared users can read. Shared
-- 'edit' users can also update. Delete stays owner-only.

drop policy if exists setlists_owner_all on public.setlists;
drop policy if exists setlists_shared_select on public.setlists;
drop policy if exists setlists_shared_update on public.setlists;

create policy setlists_owner_all on public.setlists
  for all using (auth.uid() = owner_id) with check (auth.uid() = owner_id);

create policy setlists_shared_select on public.setlists
  for select using (public.user_can_view_setlist(id));

create policy setlists_shared_update on public.setlists
  for update using (public.user_can_edit_setlist(id));

-- songs: same model, but reached indirectly through the parent setlist.
-- All cross-table checks go through the helper functions to keep RLS
-- from recursing.

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

-- setlist_shares: the setlist owner can fully manage shares; recipients
-- can see (but not modify) the shares that grant them access. The
-- owner-check goes through the helper function to avoid recursing into
-- the setlists policies.

drop policy if exists shares_owner_all        on public.setlist_shares;
drop policy if exists shares_recipient_select on public.setlist_shares;

create policy shares_owner_all on public.setlist_shares
  for all
  using      (public.user_owns_setlist(setlist_id))
  with check (public.user_owns_setlist(setlist_id));

create policy shares_recipient_select on public.setlist_shares
  for select using (shared_with = auth.uid());

-- pending_invites: the inviter can see / cancel their own invites.
-- Writes go through the SECURITY DEFINER share RPC so no INSERT/UPDATE
-- policy is needed.

drop policy if exists pending_invites_owner_select on public.pending_invites;
create policy pending_invites_owner_select on public.pending_invites
  for select using (inviter_id = auth.uid());

drop policy if exists pending_invites_owner_delete on public.pending_invites;
create policy pending_invites_owner_delete on public.pending_invites
  for delete using (inviter_id = auth.uid());

-- ── SHARING RPC ────────────────────────────────────────────────────────
-- Server-side lookup-by-email + share insert. SECURITY DEFINER so the
-- client never reads the profiles table directly; the only info that
-- escapes the function is whether the email had an account or not.
--
-- Returns:
--   { ok: true,  invited: false }  → recipient existed, share created
--   { ok: true,  invited: true  }  → recipient didn't exist, pending invite stored
--   { ok: false, error: ... }
--
-- For the invited:true case the CLIENT then calls
-- supabase.auth.signInWithOtp({email, shouldCreateUser:true}) to send
-- the magic-link sign-up email.

create or replace function public.share_setlist_by_email(
  p_setlist_id uuid,
  p_recipient_email text,
  p_permission text
) returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_owner     uuid;
  v_recipient uuid;
  v_email     text;
begin
  v_email := lower(trim(p_recipient_email));

  -- Caller must own the setlist
  select owner_id into v_owner from public.setlists where id = p_setlist_id;
  if v_owner is null then
    return jsonb_build_object('ok', false, 'error', 'setlist not found');
  end if;
  if v_owner <> auth.uid() then
    return jsonb_build_object('ok', false, 'error', 'not your setlist');
  end if;

  if p_permission not in ('view','edit') then
    return jsonb_build_object('ok', false, 'error', 'permission must be view or edit');
  end if;

  -- Look the recipient up by email
  select id into v_recipient
    from public.profiles
   where lower(email) = v_email;

  if v_recipient is not null then
    if v_recipient = auth.uid() then
      return jsonb_build_object('ok', false, 'error', 'cannot share with yourself');
    end if;
    insert into public.setlist_shares (setlist_id, shared_with, permission)
    values (p_setlist_id, v_recipient, p_permission)
    on conflict (setlist_id, shared_with) do update set permission = excluded.permission;
    return jsonb_build_object('ok', true, 'invited', false);
  end if;

  -- Recipient has no account — record a pending invite. The
  -- handle_new_user trigger will promote it to a real share when they
  -- sign up. The client side sends the magic-link email.
  insert into public.pending_invites (setlist_id, inviter_id, recipient_email, permission)
  values (p_setlist_id, auth.uid(), v_email, p_permission)
  on conflict (setlist_id, recipient_email) do update set permission = excluded.permission;

  return jsonb_build_object('ok', true, 'invited', true);
end;
$$;

grant execute on function public.share_setlist_by_email(uuid, text, text) to authenticated;

-- Done. Verify in Table Editor that the four tables exist and that RLS
-- shows as enabled (the little shield icon next to each table name).

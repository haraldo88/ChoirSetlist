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

create index if not exists setlists_owner_position_idx     on public.setlists(owner_id, position);
create index if not exists songs_setlist_position_idx      on public.songs(setlist_id, position);
create index if not exists setlist_shares_shared_with_idx  on public.setlist_shares(shared_with);

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

-- ── AUTO-CREATE PROFILE ON SIGNUP ──────────────────────────────────────
-- When a user signs up via Supabase Auth, mirror them into public.profiles
-- so the rest of the app can join against it and look them up by email.

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1))
  );
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

alter table public.profiles       enable row level security;
alter table public.setlists       enable row level security;
alter table public.songs          enable row level security;
alter table public.setlist_shares enable row level security;

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
  for select using (
    exists (
      select 1 from public.setlist_shares s
      where s.setlist_id = id and s.shared_with = auth.uid()
    )
  );

create policy setlists_shared_update on public.setlists
  for update using (
    exists (
      select 1 from public.setlist_shares s
      where s.setlist_id = id and s.shared_with = auth.uid() and s.permission = 'edit'
    )
  );

-- songs: same model, but reached indirectly through the parent setlist.

drop policy if exists songs_owner_all on public.songs;
drop policy if exists songs_shared_select on public.songs;
drop policy if exists songs_shared_mutate on public.songs;

create policy songs_owner_all on public.songs
  for all using (
    exists (
      select 1 from public.setlists sl
      where sl.id = setlist_id and sl.owner_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from public.setlists sl
      where sl.id = setlist_id and sl.owner_id = auth.uid()
    )
  );

create policy songs_shared_select on public.songs
  for select using (
    exists (
      select 1 from public.setlist_shares s
      where s.setlist_id = songs.setlist_id and s.shared_with = auth.uid()
    )
  );

create policy songs_shared_mutate on public.songs
  for all using (
    exists (
      select 1 from public.setlist_shares s
      where s.setlist_id = songs.setlist_id and s.shared_with = auth.uid() and s.permission = 'edit'
    )
  )
  with check (
    exists (
      select 1 from public.setlist_shares s
      where s.setlist_id = songs.setlist_id and s.shared_with = auth.uid() and s.permission = 'edit'
    )
  );

-- setlist_shares: the setlist owner can fully manage shares; recipients
-- can see (but not modify) the shares that grant them access.

drop policy if exists shares_owner_all on public.setlist_shares;
drop policy if exists shares_recipient_select on public.setlist_shares;

create policy shares_owner_all on public.setlist_shares
  for all using (
    exists (
      select 1 from public.setlists sl
      where sl.id = setlist_id and sl.owner_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from public.setlists sl
      where sl.id = setlist_id and sl.owner_id = auth.uid()
    )
  );

create policy shares_recipient_select on public.setlist_shares
  for select using (shared_with = auth.uid());

-- ── SHARING RPC ────────────────────────────────────────────────────────
-- Server-side lookup-by-email + share insert. We use a security-definer
-- function so the client never reads the profiles table directly; the
-- only info that escapes is whether the email exists at all.

create or replace function public.share_setlist_by_email(
  p_setlist_id uuid,
  p_recipient_email text,
  p_permission text
) returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_owner uuid;
  v_recipient uuid;
begin
  -- Caller must own the setlist
  select owner_id into v_owner from public.setlists where id = p_setlist_id;
  if v_owner is null then
    return jsonb_build_object('ok', false, 'error', 'setlist not found');
  end if;
  if v_owner <> auth.uid() then
    return jsonb_build_object('ok', false, 'error', 'not your setlist');
  end if;

  -- Permission must be 'view' or 'edit' ('copy' is handled client-side)
  if p_permission not in ('view', 'edit') then
    return jsonb_build_object('ok', false, 'error', 'permission must be view or edit');
  end if;

  -- Recipient must already have an account
  select id into v_recipient
    from public.profiles
   where lower(email) = lower(trim(p_recipient_email));
  if v_recipient is null then
    return jsonb_build_object('ok', false, 'error', 'no user with that email');
  end if;
  if v_recipient = auth.uid() then
    return jsonb_build_object('ok', false, 'error', 'cannot share with yourself');
  end if;

  insert into public.setlist_shares (setlist_id, shared_with, permission)
  values (p_setlist_id, v_recipient, p_permission)
  on conflict (setlist_id, shared_with) do update set permission = excluded.permission;

  return jsonb_build_object('ok', true);
end;
$$;

grant execute on function public.share_setlist_by_email(uuid, text, text) to authenticated;

-- Done. Verify in Table Editor that the four tables exist and that RLS
-- shows as enabled (the little shield icon next to each table name).

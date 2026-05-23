-- ───────────────────────────────────────────────────────────────────────
--  PATCH: invite-by-email for users who don't have an account yet
--
--  What's new:
--    pending_invites           — a queue of "share this setlist with
--                                this email when they sign up"
--    share_setlist_by_email    — now records a pending invite instead
--                                of erroring out if the recipient
--                                doesn't have an account
--    handle_new_user trigger   — when someone signs up, any pending
--                                invites for their email get turned
--                                into real setlist_shares automatically
--
--  How the email actually gets sent:
--    The CLIENT calls supabase.auth.signInWithOtp({email,
--    shouldCreateUser:true}) right after this RPC succeeds. That's
--    Supabase's built-in magic-link flow — no Edge Function needed.
--    The email comes from Supabase using your project's "Magic Link"
--    template (which you can customize in
--      Dashboard → Authentication → Email Templates → "Magic Link").
--
--  How to apply:
--    Supabase dashboard → SQL Editor → New query → paste this whole
--    file → Run. Safe to re-run; everything is idempotent.
-- ───────────────────────────────────────────────────────────────────────

-- ── PENDING INVITES TABLE ──────────────────────────────────────────────
-- One row per (setlist, email) you've invited. Survives until either:
--   • the email signs up (trigger converts it to a real share + deletes)
--   • the inviter explicitly cancels it

create table if not exists public.pending_invites (
  id              uuid primary key default gen_random_uuid(),
  setlist_id      uuid not null references public.setlists(id) on delete cascade,
  inviter_id      uuid not null references auth.users(id)      on delete cascade,
  recipient_email text not null,
  permission      text not null check (permission in ('view','edit')),
  created_at      timestamptz default now(),
  unique (setlist_id, recipient_email)
);

create index if not exists pending_invites_email_idx on public.pending_invites(lower(recipient_email));

alter table public.pending_invites enable row level security;

-- The inviter (= setlist owner) can see / cancel their own pending invites.
-- The RPC below uses SECURITY DEFINER to write rows so we don't need an
-- INSERT policy.

drop policy if exists pending_invites_owner_select on public.pending_invites;
create policy pending_invites_owner_select on public.pending_invites
  for select using (inviter_id = auth.uid());

drop policy if exists pending_invites_owner_delete on public.pending_invites;
create policy pending_invites_owner_delete on public.pending_invites
  for delete using (inviter_id = auth.uid());


-- ── UPDATED share_setlist_by_email RPC ─────────────────────────────────
-- Returns one of:
--   { ok: true,  invited: false }  → recipient existed, share created
--   { ok: true,  invited: true  }  → recipient didn't exist, pending invite stored
--   { ok: false, error: ... }      → failed (not your setlist / bad perm / etc)

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

  -- Look the recipient up by email (in profiles, which mirrors auth.users)
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

  -- Recipient has no account — store a pending invite. It'll be picked
  -- up by the handle_new_user trigger when they sign up.
  insert into public.pending_invites (setlist_id, inviter_id, recipient_email, permission)
  values (p_setlist_id, auth.uid(), v_email, p_permission)
  on conflict (setlist_id, recipient_email) do update set permission = excluded.permission;

  return jsonb_build_object('ok', true, 'invited', true);
end;
$$;

grant execute on function public.share_setlist_by_email(uuid, text, text) to authenticated;


-- ── UPDATED handle_new_user TRIGGER ────────────────────────────────────
-- Runs once per signup. Does two things now:
--   1. Mirror the new auth.users row into public.profiles (unchanged).
--   2. Convert any pending_invites for their email into real shares.

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer
set search_path = public
as $$
declare
  v_email text;
begin
  v_email := lower(new.email);

  -- 1. Profile row
  insert into public.profiles (id, email, display_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1))
  );

  -- 2. Promote any pending invites for this email into real shares.
  --    on conflict do update means re-running the trigger is harmless,
  --    and if the inviter changes permission later it sticks.
  insert into public.setlist_shares (setlist_id, shared_with, permission)
  select pi.setlist_id, new.id, pi.permission
    from public.pending_invites pi
   where lower(pi.recipient_email) = v_email
  on conflict (setlist_id, shared_with) do update set permission = excluded.permission;

  -- 3. Clean up the pending invites we just promoted.
  delete from public.pending_invites
   where lower(recipient_email) = v_email;

  return new;
end;
$$;

-- Trigger already exists from the original schema — recreate it to make
-- sure it points at the updated function definition.
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Done. The client side now just needs to call signInWithOtp on the
-- recipient's email after the RPC returns invited:true.

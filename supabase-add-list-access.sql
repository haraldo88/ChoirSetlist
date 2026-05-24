-- ─────────────────────────────────────────────────────────────────────
--  list_setlist_access RPC
--
--  Returns the list of people who have access to a given setlist, so
--  the owner can see who they've shared with. Two sources are merged:
--
--    • setlist_shares   — recipients who already have an account; the
--                         row stores a user_id, so we join auth.users
--                         to get the email back.
--    • pending_invites  — people invited by email who haven't signed up
--                         yet; the row already has the email.
--
--  SECURITY DEFINER because:
--    (a) we need to read auth.users.email, which RLS hides from the
--        ordinary client, and
--    (b) we want one allow-list check (`user_owns_setlist`) instead of
--        relying on RLS for two different tables.
--
--  Returned columns:
--    email      text   — the recipient's email address
--    permission text   — 'view' or 'edit'
--    status     text   — 'active'  (accepted share)
--                       'pending' (invite sent, not yet accepted)
-- ─────────────────────────────────────────────────────────────────────

create or replace function public.list_setlist_access(p_setlist_id uuid)
returns table (email text, permission text, status text)
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  -- Only the setlist owner is allowed to see the access list. We
  -- raise 42501 (insufficient_privilege) so the client can detect
  -- this distinctly from a network error.
  if not public.user_owns_setlist(p_setlist_id) then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
    with combined as (
      select u.email::text     as email,
             s.permission::text as permission,
             'active'::text     as status
        from public.setlist_shares s
        join auth.users u on u.id = s.shared_with
       where s.setlist_id = p_setlist_id
      union all
      select pi.recipient_email::text,
             pi.permission::text,
             'pending'::text
        from public.pending_invites pi
       where pi.setlist_id = p_setlist_id
    )
    select c.email, c.permission, c.status
      from combined c
     order by c.status, c.email;
end;
$$;

grant execute on function public.list_setlist_access(uuid) to authenticated;

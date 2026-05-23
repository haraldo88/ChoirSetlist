-- ───────────────────────────────────────────────────────────────────────
--  PATCH: bidirectional sync for "Can edit" shares
--
--  The client side now pushes setlist + song changes from people who
--  have been granted 'edit' permission, not just from the owner. The
--  RLS policies already allow these writes (setlists_shared_update
--  and songs_shared_mutate), so on the SQL side we only need ONE extra
--  guard: a trigger that prevents a non-owner from changing owner_id
--  via a shared-edit UPDATE. Without this, an "edit" collaborator
--  could rewrite the setlist's owner_id to themselves and effectively
--  steal it.
--
--  How to apply:
--    Supabase dashboard → SQL Editor → New query → paste this whole
--    file → Run. Safe to re-run.
-- ───────────────────────────────────────────────────────────────────────

create or replace function public.prevent_setlist_owner_change()
returns trigger language plpgsql as $$
begin
  -- If the current user isn't the row's original owner, they can't
  -- rewrite owner_id. The check runs INSIDE the row update, so it
  -- catches any path (PostgREST upsert, raw SQL, you name it).
  if new.owner_id is distinct from old.owner_id
     and old.owner_id <> auth.uid() then
    raise exception 'only the owner can change owner_id';
  end if;
  return new;
end;
$$;

drop trigger if exists prevent_setlist_owner_change on public.setlists;
create trigger prevent_setlist_owner_change
  before update on public.setlists
  for each row execute function public.prevent_setlist_owner_change();
